#!/usr/bin/env bash
#
# Materialize ee's sibling path dependencies at the exact revisions recorded
# in franken-stack.lock. Existing checkouts are reused only when their origin,
# HEAD, and clean working tree match the lock. This helper never overwrites or
# removes an existing checkout.

set -euo pipefail

usage() {
  echo "Usage: $0 DESTINATION_ROOT" >&2
  echo "Creates pinned Franken-stack repositories directly under DESTINATION_ROOT." >&2
}

die() {
  echo "franken-stack checkout: $*" >&2
  exit 1
}

if [ "$#" -ne 1 ]; then
  usage
  exit 2
fi

if ! command -v git >/dev/null 2>&1; then
  die "git is required"
fi

if ! command -v sync >/dev/null 2>&1; then
  die "sync is required for durable materialization"
fi

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPOSITORY_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
LOCK_FILE="$REPOSITORY_ROOT/franken-stack.lock"
DESTINATION_ROOT=$1

[ -f "$LOCK_FILE" ] || die "missing lock file: $LOCK_FILE"
[ -n "$DESTINATION_ROOT" ] || die "destination root must not be empty"

is_known_repository() {
  case "$1" in
    asupersync|franken_agent_detection|franken_networkx|frankensearch|frankensqlite|sqlmodel_rust|toon_rust)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

LOCK_REPOSITORIES=()
LOCK_REVISIONS=()
load_lock() {
  local count=0
  local seen='|'
  local repository
  local revision
  local remainder
  local required

  while IFS=$'\t' read -r repository revision remainder || \
        [ -n "${repository:-}${revision:-}${remainder:-}" ]; do
    case "${repository:-}" in
      ""|\#*)
        continue
        ;;
    esac

    [ -z "${remainder:-}" ] || die "malformed lock row for $repository"
    is_known_repository "$repository" || die "unknown repository in lock: $repository"
    [ "${#revision}" -eq 40 ] || die "revision for $repository is not a full 40-character commit ID"
    case "$revision" in
      *[!0-9a-f]*)
        die "revision for $repository is not lowercase hexadecimal"
        ;;
    esac
    case "$seen" in
      *"|${repository}|"*)
        die "duplicate repository in lock: $repository"
        ;;
    esac

    seen="${seen}${repository}|"
    LOCK_REPOSITORIES+=("$repository")
    LOCK_REVISIONS+=("$revision")
    count=$((count + 1))
  done < "$LOCK_FILE"

  [ "$count" -eq 7 ] || die "expected 7 locked repositories, found $count"

  for required in \
    asupersync \
    franken_agent_detection \
    franken_networkx \
    frankensearch \
    frankensqlite \
    sqlmodel_rust \
    toon_rust
  do
    case "$seen" in
      *"|${required}|"*)
        ;;
      *)
        die "required repository missing from lock: $required"
        ;;
    esac
  done
}

load_lock

assert_no_symlink_components() {
  local candidate=$1
  local absolute
  local prefix
  local component
  local components=()

  case "$candidate" in
    /*)
      absolute=$candidate
      ;;
    *)
      absolute="$(pwd -P)/$candidate"
      ;;
  esac

  prefix=/
  IFS='/' read -r -a components <<< "${absolute#/}"
  for component in "${components[@]}"; do
    [ -n "$component" ] || continue
    prefix="${prefix%/}/$component"
    [ ! -L "$prefix" ] || die "$prefix is a symlink; refusing to modify it"
  done
}

assert_no_symlink_components "$DESTINATION_ROOT"
mkdir -p "$DESTINATION_ROOT"
assert_no_symlink_components "$DESTINATION_ROOT"
DESTINATION_ROOT=$(CDPATH='' cd -- "$DESTINATION_ROOT" && pwd -P)
[ "$DESTINATION_ROOT" != "/" ] || die "refusing to populate the filesystem root"

STAGING_ROOT="$DESTINATION_ROOT/.ee-franken-stack-staging"
STAGING_MARKER_NAME="ee-franken-stack-staging-v1"
MANAGED_MARKER_NAME="ee-franken-stack-managed"
CURRENT_STAGE=''
CURRENT_STAGE_ATTESTED=0
CURRENT_TEMP=''

cleanup() {
  local status=$?

  if [ -n "$CURRENT_TEMP" ] && [ -e "$CURRENT_TEMP" ]; then
    # This is always a uniquely named temporary marker owned by this process.
    rm -f -- "$CURRENT_TEMP"
  fi
  if [ "$status" -ne 0 ] && [ -n "$CURRENT_STAGE" ] && [ -d "$CURRENT_STAGE" ]; then
    if [ "$CURRENT_STAGE_ATTESTED" -eq 1 ] || \
       [ -f "$CURRENT_STAGE/.git/$STAGING_MARKER_NAME" ]; then
      echo "franken-stack checkout: preserved resumable staging at $CURRENT_STAGE" >&2
    else
      echo "franken-stack checkout: preserved incomplete staging at $CURRENT_STAGE; destination remains absent" >&2
    fi
  fi
  if [ -d "$STAGING_ROOT" ]; then
    rmdir -- "$STAGING_ROOT" 2>/dev/null || true
  fi
  return "$status"
}

trap cleanup EXIT

fsync_path() {
  local path=$1

  sync -f "$path" >/dev/null 2>&1 || \
    die "could not fsync $path"
}

write_atomic_text() {
  local destination=$1
  local contents=$2
  local temporary
  local temporary_fsync_failed=0

  [ ! -L "$destination" ] || die "$destination is a symlink; refusing to replace it"
  [ ! -e "$destination" ] || die "$destination already exists; refusing to replace it"
  if ! temporary=$(mktemp "${destination}.tmp.XXXXXX"); then
    die "could not create a temporary marker beside $destination"
  fi
  CURRENT_TEMP=$temporary
  if ! printf '%s\n' "$contents" > "$temporary"; then
    die "could not write temporary marker beside $destination"
  fi
  # Publish the complete temporary file before the durability check. If the
  # filesystem refuses fsync, the attestation remains available for a safe
  # retry instead of leaving an unmarked Git directory behind.
  if ! sync -f "$temporary" >/dev/null 2>&1; then
    temporary_fsync_failed=1
  fi
  if ! mv -- "$temporary" "$destination"; then
    die "could not publish marker $destination"
  fi
  CURRENT_TEMP=''
  [ "$temporary_fsync_failed" -eq 0 ] || \
    die "could not fsync $destination"
  fsync_path "$destination"
  fsync_path "$(dirname -- "$destination")"
}

verify_staging_tree() {
  local entry
  local repository

  [ -e "$STAGING_ROOT" ] || [ -L "$STAGING_ROOT" ] || return 0
  [ ! -L "$STAGING_ROOT" ] || \
    die "$STAGING_ROOT is a symlink; refusing to inspect it"
  [ -d "$STAGING_ROOT" ] || die "$STAGING_ROOT is not a directory"

  # A resumable staging root is part of the helper's state machine. Every
  # child must therefore be one of the seven locked repositories; an unknown
  # child could otherwise survive a successful run and be mistaken for a
  # trusted checkout later.
  for entry in "$STAGING_ROOT"/* "$STAGING_ROOT"/.[!.]* "$STAGING_ROOT"/..?*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    repository=${entry##*/}
    is_known_repository "$repository" || \
      die "$STAGING_ROOT contains unknown staged tree: $repository"
    [ -d "$entry" ] && [ ! -L "$entry" ] || \
      die "$entry is not a regular staged directory"
  done
}

origin_matches() {
  local repository=$1
  local expected_url=$2
  local actual_url=$3

  case "$actual_url" in
    "$expected_url"|"${expected_url%.git}"|"git@github.com:Dicklesworthstone/${repository}.git")
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

checkout_status() {
  local destination=$1
  git -C "$destination" status --porcelain --untracked-files=normal
}

checkout_identity_matches() {
  local repository=$1
  local revision=$2
  local destination=$3
  local expected_url=$4
  local actual_revision
  local actual_url

  actual_revision=$(git -C "$destination" rev-parse HEAD 2>/dev/null || true)
  [ "$actual_revision" = "$revision" ] || return 1

  actual_url=$(git -C "$destination" remote get-url origin 2>/dev/null || true)
  origin_matches "$repository" "$expected_url" "$actual_url" || return 1
}

verify_clean_checkout() {
  local repository=$1
  local revision=$2
  local destination=$3
  local expected_url=$4
  local status

  checkout_identity_matches "$repository" "$revision" "$destination" "$expected_url" || return 1
  if ! status=$(checkout_status "$destination"); then
    return 1
  fi
  [ -z "$status" ]
}

staging_marker_contents() {
  local repository=$1
  local revision=$2
  local repository_url=$3

  printf '%s\nrepository=%s\nrevision=%s\norigin=%s' \
    "$STAGING_MARKER_NAME" "$repository" "$revision" "$repository_url"
}

managed_marker_contents() {
  printf '%s\t%s' "$1" "$2"
}

verify_staging_marker() {
  local stage=$1
  local repository=$2
  local revision=$3
  local repository_url=$4
  local marker="$stage/.git/$STAGING_MARKER_NAME"
  local marker_value

  [ ! -L "$marker" ] || die "$marker is a symlink; refusing to trust it"
  [ -f "$marker" ] || die "$stage has no staging attestation; refusing to resume it"
  marker_value=$(< "$marker")
  [ "$marker_value" = "$(staging_marker_contents "$repository" "$revision" "$repository_url")" ] || \
    die "$stage has an unexpected staging attestation; refusing to resume it"
}

publish_staged_checkout() {
  local repository=$1
  local revision=$2
  local stage=$3
  local destination=$4

  [ ! -e "$destination" ] && [ ! -L "$destination" ] || \
    die "$destination appeared while staging; refusing to overwrite it"
  [ ! -L "$stage" ] || die "$stage is a symlink; refusing to publish it"
  fsync_path "$stage/.git"
  fsync_path "$stage"
  # DESTINATION_ROOT and STAGING_ROOT are on the same filesystem by construction.
  mv -- "$stage" "$destination"
  CURRENT_STAGE=''
  CURRENT_STAGE_ATTESTED=0
  fsync_path "$DESTINATION_ROOT"
  echo "franken-stack: checked out ${repository}@${revision}"
}

checkout_repository() {
  local repository=$1
  local revision=$2
  local destination="$DESTINATION_ROOT/$repository"
  local repository_url="https://github.com/Dicklesworthstone/${repository}.git"
  local stage="$STAGING_ROOT/$repository"
  local marker
  local marker_value
  local status

  [ ! -L "$destination" ] || \
    die "$destination is a symlink; refusing to modify it"
  [ ! -L "$stage" ] || \
    die "$stage is a symlink; refusing to modify it"
  verify_staging_tree

  if [ -e "$destination" ]; then
    [ ! -e "$stage" ] || \
      die "$destination and its resumable staging both exist; refusing to choose between them"
    [ ! -L "$destination/.git" ] || \
      die "$destination/.git is a symlink; refusing to trust it"
    [ -d "$destination/.git" ] || \
      die "$destination already exists and is not a regular Git checkout"

    marker="$destination/.git/$MANAGED_MARKER_NAME"
    [ ! -L "$marker" ] || \
      die "$marker is a symlink; refusing to trust it"
    [ -f "$marker" ] || \
      die "$destination has no managed checkout marker; refusing to modify it"
    marker_value=$(< "$marker")
    [ "$marker_value" = "$(managed_marker_contents "$repository" "$revision")" ] || \
      die "$destination does not exactly match ${repository}@${revision}; refusing to modify it"
    marker="$destination/.git/$STAGING_MARKER_NAME"
    if [ -e "$marker" ] || [ -L "$marker" ]; then
      verify_staging_marker "$destination" "$repository" "$revision" "$repository_url"
    fi
    verify_clean_checkout "$repository" "$revision" "$destination" "$repository_url" || \
      die "$destination is dirty or has unexpected provenance; refusing to modify it"
    echo "franken-stack: reuse ${repository}@${revision}"
    return 0
  fi

  if [ -e "$STAGING_ROOT" ] || [ -L "$STAGING_ROOT" ]; then
    [ ! -L "$STAGING_ROOT" ] || \
      die "$STAGING_ROOT is a symlink; refusing to modify it"
    [ -d "$STAGING_ROOT" ] || die "$STAGING_ROOT is not a directory"
  else
    mkdir "$STAGING_ROOT"
  fi

  if [ -e "$stage" ]; then
    [ -d "$stage" ] || die "$stage is not a directory; refusing to resume it"
    [ ! -L "$stage/.git" ] || \
      die "$stage/.git is a symlink; refusing to trust it"
    [ -d "$stage/.git" ] || die "$stage has no regular Git metadata; refusing to resume it"
    verify_staging_marker "$stage" "$repository" "$revision" "$repository_url"
    CURRENT_STAGE_ATTESTED=1
  else
    mkdir "$stage"
    CURRENT_STAGE=$stage
    git -C "$stage" init -q
    git -C "$stage" remote add origin "$repository_url"
    write_atomic_text "$stage/.git/$STAGING_MARKER_NAME" \
      "$(staging_marker_contents "$repository" "$revision" "$repository_url")"
    CURRENT_STAGE_ATTESTED=1
  fi

  CURRENT_STAGE=$stage
  if ! status=$(checkout_status "$stage"); then
    die "$stage is not a usable Git checkout; refusing to resume it"
  fi
  [ -z "$status" ] || \
    die "$stage has unknown local changes; refusing to overwrite staged files"

  if ! checkout_identity_matches "$repository" "$revision" "$stage" "$repository_url"; then
    git -C "$stage" fetch --depth 1 origin "$revision"
    git -C "$stage" -c advice.detachedHead=false checkout --detach FETCH_HEAD
  fi

  verify_clean_checkout "$repository" "$revision" "$stage" "$repository_url" || \
    die "$repository staging is dirty or has unexpected provenance after checkout"
  marker="$stage/.git/$MANAGED_MARKER_NAME"
  if [ -e "$marker" ] || [ -L "$marker" ]; then
    [ ! -L "$marker" ] || die "$marker is a symlink; refusing to trust it"
    [ -f "$marker" ] || die "$marker is not a regular file; refusing to trust it"
    marker_value=$(< "$marker")
    [ "$marker_value" = "$(managed_marker_contents "$repository" "$revision")" ] || \
      die "$stage has an unexpected managed checkout marker; refusing to resume it"
  else
    write_atomic_text "$marker" "$(managed_marker_contents "$repository" "$revision")"
  fi

  publish_staged_checkout "$repository" "$revision" "$stage" "$destination"
}

# The locked SQLModel revision currently uses a normal semver requirement for
# asupersync (0.4.9), which is compatible with ee's locked 0.4.10 path patch.
# Keep the sibling checkout byte-for-byte clean: rewriting Cargo.toml here
# would make the result non-idempotent and would hide its source provenance.
# If a future lock reintroduces an incompatible or unsupported requirement,
# fail closed and refresh the lock instead of silently editing an upstream
# checkout.
is_cargo_caret_compatible() {
  local requirement=$1
  local locked_version=$2
  local normalized_requirement
  local req_major
  local req_minor
  local req_patch
  local locked_major
  local locked_minor
  local locked_patch

  normalized_requirement=$requirement
  case "$normalized_requirement" in
    ^*) normalized_requirement=${normalized_requirement#^} ;;
  esac
  [[ "$normalized_requirement" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 1
  req_major=$((10#${BASH_REMATCH[1]}))
  req_minor=$((10#${BASH_REMATCH[2]}))
  req_patch=$((10#${BASH_REMATCH[3]}))
  [[ "$locked_version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 1
  locked_major=$((10#${BASH_REMATCH[1]}))
  locked_minor=$((10#${BASH_REMATCH[2]}))
  locked_patch=$((10#${BASH_REMATCH[3]}))

  if [ "$req_major" -eq 0 ]; then
    [ "$locked_major" -eq 0 ] || return 1
    [ "$locked_minor" -eq "$req_minor" ] || return 1
    if [ "$req_minor" -eq 0 ]; then
      # Cargo's ^0.0.x range is [0.0.x, 0.0.(x+1)), so only x matches.
      [ "$locked_patch" -eq "$req_patch" ]
      return
    fi
    [ "$locked_patch" -ge "$req_patch" ]
    return
  fi

  [ "$locked_major" -eq "$req_major" ] || return 1
  if [ "$locked_minor" -gt "$req_minor" ]; then
    return 0
  fi
  [ "$locked_minor" -eq "$req_minor" ] || return 1
  [ "$locked_patch" -ge "$req_patch" ]
}

verify_sqlmodel_asupersync_compatibility() {
  local asu_toml="$DESTINATION_ROOT/asupersync/Cargo.toml"
  local sql_toml="$DESTINATION_ROOT/sqlmodel_rust/Cargo.toml"
  local asu_ver
  local requirements
  local requirement_count
  local requirement

  [ -f "$asu_toml" ] && [ -f "$sql_toml" ] || \
    die "missing asupersync or SQLModel manifest after checkout"
  asu_ver=$(sed -n \
    's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([0-9][0-9.]*\)"[[:space:]]*$/\1/p' \
    "$asu_toml" | head -n 1)
  [ -n "$asu_ver" ] || die "could not determine the locked asupersync version"

  requirements=''
  local line
  local requirement_from_line
  local string_dependency_pattern='^[[:space:]]*asupersync[[:space:]]*=[[:space:]]*"([^"]*)"[[:space:]]*$'
  local inline_dependency_pattern='^[[:space:]]*asupersync[[:space:]]*=[[:space:]]*\{(.*)\}[[:space:]]*$'
  local inline_version_pattern='(^|[,[:space:]])version[[:space:]]*=[[:space:]]*"([^"]*)"'

  # Cargo permits either a shorthand string dependency or an inline table.
  # Keep the extraction line-oriented because Cargo inline tables themselves
  # cannot contain a newline, while accepting arbitrary field order and
  # whitespace around the assignment.
  extract_sqlmodel_requirement() {
    local dependency_line=$1
    local inline_table

    dependency_line=${dependency_line%%#*}
    if [[ "$dependency_line" =~ $string_dependency_pattern ]]; then
      printf '%s\n' "${BASH_REMATCH[1]}"
      return 0
    fi
    if [[ "$dependency_line" =~ $inline_dependency_pattern ]]; then
      inline_table=${BASH_REMATCH[1]}
      if [[ "$inline_table" =~ $inline_version_pattern ]]; then
        printf '%s\n' "${BASH_REMATCH[2]}"
        return 0
      fi
    fi
    return 1
  }

  while IFS= read -r line; do
    if requirement_from_line=$(extract_sqlmodel_requirement "$line"); then
      if [ -n "$requirements" ]; then
        requirements+=$'\n'
      fi
      requirements+=$requirement_from_line
    fi
  done < "$sql_toml"
  requirement_count=$(printf '%s\n' "$requirements" | awk 'NF { count++ } END { print count + 0 }')
  [ "$requirement_count" -le 1 ] || \
    die "SQLModel has multiple asupersync requirements; refusing ambiguous materialization"
  [ "$requirement_count" -eq 1 ] || return 0

  requirement=$requirements
  case "$requirement" in
    =*)
      [ "${requirement#=}" = "$asu_ver" ] || \
        die "locked SQLModel requires asupersync $requirement but locked asupersync is $asu_ver; refusing to rewrite Cargo.toml"
      echo "franken-stack: verified SQLModel exact asupersync pin =${asu_ver}"
      ;;
    ^*|[0-9]*)
      is_cargo_caret_compatible "$requirement" "$asu_ver" || \
        die "locked SQLModel requirement $requirement is incompatible with asupersync $asu_ver; refusing to rewrite Cargo.toml"
      echo "franken-stack: verified SQLModel asupersync requirement ${requirement} against ${asu_ver}"
      ;;
    *)
      die "locked SQLModel uses unsupported asupersync requirement $requirement; refusing to rewrite Cargo.toml"
      ;;
  esac
}

verify_staging_tree

for index in "${!LOCK_REPOSITORIES[@]}"; do
  checkout_repository "${LOCK_REPOSITORIES[$index]}" "${LOCK_REVISIONS[$index]}"
done

verify_staging_tree

verify_sqlmodel_asupersync_compatibility
