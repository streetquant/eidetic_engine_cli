#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CHECKOUT_SCRIPT="$SCRIPT_DIR/checkout-franken-stack.sh"

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'checkout-franken-stack fixture: required tool missing: %s\n' "$1" >&2
    exit 2
  }
}

assert_file() {
  [ -f "$1" ] || {
    printf 'checkout-franken-stack fixture: expected file: %s\n' "$1" >&2
    exit 1
  }
}

assert_directory() {
  [ -d "$1" ] || {
    printf 'checkout-franken-stack fixture: expected directory: %s\n' "$1" >&2
    exit 1
  }
}

assert_absent() {
  [ ! -e "$1" ] && [ ! -L "$1" ] || {
    printf 'checkout-franken-stack fixture: expected absent path: %s\n' "$1" >&2
    exit 1
  }
}

require_tool git
require_tool sync
assert_file "$CHECKOUT_SCRIPT"
bash -n "$CHECKOUT_SCRIPT"

FIXTURE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/ee-checkout-franken-stack.XXXXXX")
REMOTE_ROOT="$FIXTURE_ROOT/remotes"
WORK_ROOT="$FIXTURE_ROOT/work"
SOURCE_ROOT="$FIXTURE_ROOT/source"
BIN_ROOT="$FIXTURE_ROOT/bin"
mkdir -p "$REMOTE_ROOT" "$WORK_ROOT" "$SOURCE_ROOT/scripts" "$BIN_ROOT"

printf 'checkout-franken-stack fixture artifacts: %s\n' "$FIXTURE_ROOT" >&2

REAL_GIT=$(command -v git)
REAL_SYNC=$(command -v sync)
ORIGINAL_PATH=$PATH

seed_repository() {
  local repository=$1
  local work="$WORK_ROOT/$repository"
  local remote="$REMOTE_ROOT/$repository.git"

  git init --bare -q "$remote"
  git init -q "$work"
  git -C "$work" config user.name fixture
  git -C "$work" config user.email fixture@example.invalid
  case "$repository" in
    asupersync)
      cat > "$work/Cargo.toml" <<'MANIFEST'
[package]
name = "asupersync"
version = "0.4.9"
edition = "2024"
MANIFEST
      ;;
    sqlmodel_rust)
      cat > "$work/Cargo.toml" <<'MANIFEST'
[workspace]

[workspace.dependencies]
asupersync = { version = "0.4.9", default-features = false }
MANIFEST
      ;;
    *)
      printf 'fixture repository %s\n' "$repository" > "$work/README.md"
      ;;
  esac
  git -C "$work" add .
  git -C "$work" commit -qm 'fixture seed'
  git -C "$work" remote add origin "$remote"
  git -C "$work" push -q origin HEAD:refs/heads/main
}

for repository in \
  asupersync \
  franken_agent_detection \
  franken_networkx \
  frankensearch \
  frankensqlite \
  sqlmodel_rust \
  toon_rust
do
  seed_repository "$repository"
done

REV_ASUPERSYNC=$(git -C "$WORK_ROOT/asupersync" rev-parse HEAD)
REV_AGENT=$(git -C "$WORK_ROOT/franken_agent_detection" rev-parse HEAD)
REV_NETWORKX=$(git -C "$WORK_ROOT/franken_networkx" rev-parse HEAD)
REV_SEARCH=$(git -C "$WORK_ROOT/frankensearch" rev-parse HEAD)
REV_SQLITE=$(git -C "$WORK_ROOT/frankensqlite" rev-parse HEAD)
REV_SQLMODEL=$(git -C "$WORK_ROOT/sqlmodel_rust" rev-parse HEAD)
REV_TOON=$(git -C "$WORK_ROOT/toon_rust" rev-parse HEAD)

write_lock() {
  local lock_file=$1
  local asupersync_revision=$2
  local sqlmodel_revision=$3

  {
    printf 'asupersync\t%s\n' "$asupersync_revision"
    printf 'franken_agent_detection\t%s\n' "$REV_AGENT"
    printf 'franken_networkx\t%s\n' "$REV_NETWORKX"
    printf 'frankensearch\t%s\n' "$REV_SEARCH"
    printf 'frankensqlite\t%s\n' "$REV_SQLITE"
    printf 'sqlmodel_rust\t%s\n' "$sqlmodel_revision"
    printf 'toon_rust\t%s\n' "$REV_TOON"
  } > "$lock_file"
}

cp "$CHECKOUT_SCRIPT" "$SOURCE_ROOT/scripts/checkout-franken-stack.sh"
chmod +x "$SOURCE_ROOT/scripts/checkout-franken-stack.sh"
write_lock "$SOURCE_ROOT/franken-stack.lock" "$REV_ASUPERSYNC" "$REV_SQLMODEL"
ACTIVE_SOURCE_ROOT="$SOURCE_ROOT"
EXPECTED_REV_ASUPERSYNC="$REV_ASUPERSYNC"
EXPECTED_REV_SQLMODEL="$REV_SQLMODEL"

cat > "$BIN_ROOT/git" <<'GIT_WRAPPER'
#!/usr/bin/env bash

set -euo pipefail

real_git=${EE_FIXTURE_REAL_GIT:?}
remote_root=${EE_FIXTURE_REMOTE_ROOT:?}
fail_repo=${EE_FIXTURE_FAIL_REPO:-}
fail_once=${EE_FIXTURE_FAIL_ONCE:-}
fetch_delay=${EE_FIXTURE_FETCH_DELAY:-}
fetch_log=${EE_FIXTURE_FETCH_LOG:-}
repository_path=''

if [ "${1:-}" = '-C' ]; then
  repository_path=$2
fi

if [ "${1:-}" = '-C' ] && [ "${3:-}" = fetch ] && \
   [ "$(basename "$repository_path")" = "$fail_repo" ] && \
   [ -n "$fail_once" ] && [ ! -e "$fail_once" ]; then
  : > "$fail_once"
  printf 'fixture: injected fetch failure for %s\n' "$fail_repo" >&2
  exit 77
fi

if [ "${1:-}" = '-C' ] && [ "${3:-}" = fetch ]; then
  if [ -n "$fetch_log" ]; then
    printf '%s\n' "$(basename "$repository_path")" >> "$fetch_log"
  fi
  if [ -n "$fetch_delay" ]; then
    sleep "$fetch_delay"
  fi
fi

if [ "${1:-}" = '-C' ] && [ "${3:-}" = remote ] && \
   [ "${4:-}" = get-url ] && [ "${5:-}" = origin ]; then
  repository=$(basename "$repository_path")
  actual=$($real_git "$@")
  case "$actual" in
    "file://${remote_root}/${repository}.git"|"file://${remote_root}/${repository}")
      printf 'https://github.com/Dicklesworthstone/%s.git\n' "$repository"
      ;;
    *)
      printf '%s\n' "$actual"
      ;;
  esac
  exit 0
fi

rewritten=()
for argument in "$@"; do
  case "$argument" in
    https://github.com/Dicklesworthstone/*.git)
      repository=${argument##*/}
      repository=${repository%.git}
      rewritten+=("file://${remote_root}/${repository}.git")
      ;;
    *)
      rewritten+=("$argument")
      ;;
  esac
done

exec "$real_git" "${rewritten[@]}"
GIT_WRAPPER
chmod +x "$BIN_ROOT/git"

cat > "$BIN_ROOT/sync" <<'SYNC_WRAPPER'
#!/usr/bin/env bash

set -euo pipefail

real_sync=${EE_FIXTURE_REAL_SYNC:?}
fail_once=${EE_FIXTURE_SYNC_FAIL_ONCE:-}
if [ -n "$fail_once" ] && [ ! -e "$fail_once" ]; then
  : > "$fail_once"
  printf 'fixture: injected fsync failure\n' >&2
  exit 78
fi
exec "$real_sync" "$@"
SYNC_WRAPPER
chmod +x "$BIN_ROOT/sync"

EE_FIXTURE_FAIL_REPO=''
EE_FIXTURE_FAIL_ONCE=''
EE_FIXTURE_SYNC_FAIL_ONCE=''
run_helper() {
  local destination=$1

  PATH="$BIN_ROOT:$ORIGINAL_PATH" \
    EE_FIXTURE_REAL_GIT="$REAL_GIT" \
    EE_FIXTURE_REAL_SYNC="$REAL_SYNC" \
    EE_FIXTURE_REMOTE_ROOT="$REMOTE_ROOT" \
    EE_FIXTURE_FAIL_REPO="$EE_FIXTURE_FAIL_REPO" \
    EE_FIXTURE_FAIL_ONCE="$EE_FIXTURE_FAIL_ONCE" \
    EE_FIXTURE_SYNC_FAIL_ONCE="$EE_FIXTURE_SYNC_FAIL_ONCE" \
    EE_FIXTURE_FETCH_DELAY="${EE_FIXTURE_FETCH_DELAY:-}" \
    EE_FIXTURE_FETCH_LOG="${EE_FIXTURE_FETCH_LOG:-}" \
    "$ACTIVE_SOURCE_ROOT/scripts/checkout-franken-stack.sh" "$destination"
}

assert_clean_materialization() {
  local destination=$1
  local repository
  local revision
  local marker

  for repository in \
    asupersync \
    franken_agent_detection \
    franken_networkx \
    frankensearch \
    frankensqlite \
    sqlmodel_rust \
    toon_rust
  do
    assert_directory "$destination/$repository/.git"
    if [ -n "$(git -C "$destination/$repository" status --porcelain --untracked-files=normal)" ]; then
      printf 'checkout-franken-stack fixture: %s is dirty\n' "$repository" >&2
      exit 1
    fi
    revision=$EXPECTED_REV_ASUPERSYNC
    case "$repository" in
      franken_agent_detection) revision=$REV_AGENT ;;
      franken_networkx) revision=$REV_NETWORKX ;;
      frankensearch) revision=$REV_SEARCH ;;
      frankensqlite) revision=$REV_SQLITE ;;
      sqlmodel_rust) revision=$EXPECTED_REV_SQLMODEL ;;
      toon_rust) revision=$REV_TOON ;;
    esac
    [ "$(git -C "$destination/$repository" rev-parse HEAD)" = "$revision" ] || {
      printf 'checkout-franken-stack fixture: %s has the wrong revision\n' "$repository" >&2
      exit 1
    }
    marker=$(cat "$destination/$repository/.git/ee-franken-stack-managed")
    [ "$marker" = "$(printf '%s\t%s' "$repository" "$revision")" ] || {
      printf 'checkout-franken-stack fixture: %s has the wrong marker\n' "$repository" >&2
      exit 1
    }
    assert_file "$destination/$repository/.git/ee-franken-stack-staging-v1"
  done
}

fresh_destination() {
  local name=$1
  local destination="$FIXTURE_ROOT/$name"
  mkdir "$destination"
  printf '%s\n' "$destination"
}

initial_destination=$(fresh_destination initial)
run_helper "$initial_destination" > "$FIXTURE_ROOT/initial.log" 2>&1
assert_clean_materialization "$initial_destination"
run_helper "$initial_destination" > "$FIXTURE_ROOT/reuse.log" 2>&1
grep -F 'reuse asupersync@' "$FIXTURE_ROOT/reuse.log" >/dev/null
grep -F 'verified SQLModel asupersync requirement 0.4.9 against 0.4.9' "$FIXTURE_ROOT/reuse.log" >/dev/null
assert_absent "$initial_destination/.ee-franken-stack-staging"

mkdir -p "$initial_destination/.ee-franken-stack-staging"
printf 'unknown staged tree\n' > "$initial_destination/.ee-franken-stack-staging/rogue"
set +e
run_helper "$initial_destination" > "$FIXTURE_ROOT/unknown-staging.log" 2>&1
unknown_staging_status=$?
set -e
[ "$unknown_staging_status" -ne 0 ]
grep -F 'contains unknown staged tree: rogue' "$FIXTURE_ROOT/unknown-staging.log" >/dev/null
rm -f -- "$initial_destination/.ee-franken-stack-staging/rogue"
rmdir "$initial_destination/.ee-franken-stack-staging"

invalid_lock_source="$FIXTURE_ROOT/invalid-lock-source"
mkdir -p "$invalid_lock_source/scripts"
cp "$CHECKOUT_SCRIPT" "$invalid_lock_source/scripts/checkout-franken-stack.sh"
chmod +x "$invalid_lock_source/scripts/checkout-franken-stack.sh"
cp "$SOURCE_ROOT/franken-stack.lock" "$invalid_lock_source/franken-stack.lock"
printf 'unknown_repository\t%s\n' "$REV_AGENT" >> "$invalid_lock_source/franken-stack.lock"
ACTIVE_SOURCE_ROOT="$invalid_lock_source"
invalid_lock_destination=$(fresh_destination invalid-lock)
set +e
run_helper "$invalid_lock_destination" > "$FIXTURE_ROOT/invalid-lock.log" 2>&1
invalid_lock_status=$?
set -e
[ "$invalid_lock_status" -ne 0 ]
assert_absent "$invalid_lock_destination/.ee-franken-stack-staging"
assert_absent "$invalid_lock_destination/asupersync"
grep -F 'unknown repository in lock: unknown_repository' "$FIXTURE_ROOT/invalid-lock.log" >/dev/null
ACTIVE_SOURCE_ROOT="$SOURCE_ROOT"

test_cargo_requirement() {
  local name=$1
  local declaration=$2
  local expected_log=$3
  local source="$FIXTURE_ROOT/$name-source"
  local revision
  local destination

  printf '[workspace]\n\n[workspace.dependencies]\n%s\n' "$declaration" > "$WORK_ROOT/sqlmodel_rust/Cargo.toml"
  git -C "$WORK_ROOT/sqlmodel_rust" add Cargo.toml
  git -C "$WORK_ROOT/sqlmodel_rust" commit -qm "fixture SQLModel $name requirement"
  git -C "$WORK_ROOT/sqlmodel_rust" push -q origin HEAD:refs/heads/main
  revision=$(git -C "$WORK_ROOT/sqlmodel_rust" rev-parse HEAD)

  mkdir -p "$source/scripts"
  cp "$CHECKOUT_SCRIPT" "$source/scripts/checkout-franken-stack.sh"
  chmod +x "$source/scripts/checkout-franken-stack.sh"
  write_lock "$source/franken-stack.lock" "$REV_ASUPERSYNC" "$revision"
  ACTIVE_SOURCE_ROOT="$source"
  EXPECTED_REV_SQLMODEL="$revision"
  destination=$(fresh_destination "$name")
  run_helper "$destination" > "$FIXTURE_ROOT/$name.log" 2>&1
  assert_clean_materialization "$destination"
  grep -F "$expected_log" "$FIXTURE_ROOT/$name.log" >/dev/null
}

test_cargo_requirement inline-caret \
  'asupersync = { default-features = false, version = "^0.4.9" }' \
  'verified SQLModel asupersync requirement ^0.4.9 against 0.4.9'
test_cargo_requirement shorthand \
  'asupersync = "0.4.9"' \
  'verified SQLModel asupersync requirement 0.4.9 against 0.4.9'
test_cargo_requirement inline-exact \
  'asupersync = { version = "=0.4.9", default-features = false }' \
  'verified SQLModel exact asupersync pin =0.4.9'

# Restore the baseline manifest before the independent 0.0.x boundary cases.
cat > "$WORK_ROOT/sqlmodel_rust/Cargo.toml" <<'MANIFEST'
[workspace]

[workspace.dependencies]
asupersync = { version = "0.4.9", default-features = false }
MANIFEST
git -C "$WORK_ROOT/sqlmodel_rust" add Cargo.toml
git -C "$WORK_ROOT/sqlmodel_rust" commit -qm 'fixture restore baseline SQLModel requirement'
git -C "$WORK_ROOT/sqlmodel_rust" push -q origin HEAD:refs/heads/main
ACTIVE_SOURCE_ROOT="$SOURCE_ROOT"
EXPECTED_REV_SQLMODEL="$REV_SQLMODEL"

printf '\nunknown fixture edit\n' >> "$initial_destination/sqlmodel_rust/Cargo.toml"
set +e
run_helper "$initial_destination" > "$FIXTURE_ROOT/dirty.log" 2>&1
dirty_status=$?
set -e
[ "$dirty_status" -ne 0 ]
grep -F 'refusing to modify it' "$FIXTURE_ROOT/dirty.log" >/dev/null
grep -F 'unknown fixture edit' "$initial_destination/sqlmodel_rust/Cargo.toml" >/dev/null

fetch_failure_destination=$(fresh_destination fetch-failure)
EE_FIXTURE_FAIL_REPO=asupersync
EE_FIXTURE_FAIL_ONCE="$FIXTURE_ROOT/fetch-failure.once"
set +e
run_helper "$fetch_failure_destination" > "$FIXTURE_ROOT/fetch-failure.log" 2>&1
fetch_status=$?
set -e
[ "$fetch_status" -eq 77 ]
assert_absent "$fetch_failure_destination/asupersync"
assert_file "$fetch_failure_destination/.ee-franken-stack-staging/asupersync/.git/ee-franken-stack-staging-v1"
grep -F 'preserved resumable staging' "$FIXTURE_ROOT/fetch-failure.log" >/dev/null
run_helper "$fetch_failure_destination" > "$FIXTURE_ROOT/fetch-resume.log" 2>&1
assert_clean_materialization "$fetch_failure_destination"
assert_absent "$fetch_failure_destination/.ee-franken-stack-staging"

poisoned_origin_destination=$(fresh_destination poisoned-origin)
EE_FIXTURE_FAIL_REPO=asupersync
EE_FIXTURE_FAIL_ONCE="$FIXTURE_ROOT/poisoned-origin.once"
EE_FIXTURE_FETCH_DELAY=''
EE_FIXTURE_FETCH_LOG=''
set +e
run_helper "$poisoned_origin_destination" > "$FIXTURE_ROOT/poisoned-origin-seed.log" 2>&1
poisoned_seed_status=$?
set -e
[ "$poisoned_seed_status" -eq 77 ]
poisoned_stage="$poisoned_origin_destination/.ee-franken-stack-staging/asupersync"
assert_file "$poisoned_stage/.git/ee-franken-stack-staging-v1"
git -C "$poisoned_stage" remote set-url origin "file://$FIXTURE_ROOT/poisoned-origin.git"
EE_FIXTURE_FAIL_REPO=''
EE_FIXTURE_FAIL_ONCE=''
EE_FIXTURE_FETCH_LOG="$FIXTURE_ROOT/poisoned-origin.fetches"
: > "$EE_FIXTURE_FETCH_LOG"
set +e
run_helper "$poisoned_origin_destination" > "$FIXTURE_ROOT/poisoned-origin.log" 2>&1
poisoned_status=$?
set -e
[ "$poisoned_status" -ne 0 ]
grep -F 'has unexpected origin; refusing to fetch from it' "$FIXTURE_ROOT/poisoned-origin.log" >/dev/null
[ ! -s "$EE_FIXTURE_FETCH_LOG" ]
git -C "$poisoned_stage" remote set-url origin "file://$REMOTE_ROOT/asupersync.git"
EE_FIXTURE_FETCH_LOG=''
run_helper "$poisoned_origin_destination" > "$FIXTURE_ROOT/poisoned-origin-resume.log" 2>&1
assert_clean_materialization "$poisoned_origin_destination"
assert_absent "$poisoned_origin_destination/.ee-franken-stack-staging"

sync_failure_destination=$(fresh_destination sync-failure)
EE_FIXTURE_FAIL_REPO=''
EE_FIXTURE_FAIL_ONCE=''
EE_FIXTURE_SYNC_FAIL_ONCE="$FIXTURE_ROOT/sync-failure.once"
set +e
run_helper "$sync_failure_destination" > "$FIXTURE_ROOT/sync-failure.log" 2>&1
sync_status=$?
set -e
[ "$sync_status" -ne 0 ]
assert_absent "$sync_failure_destination/asupersync"
assert_file "$sync_failure_destination/.ee-franken-stack-staging/asupersync/.git/ee-franken-stack-staging-v1"
assert_absent "$sync_failure_destination/.ee-franken-stack-staging/asupersync/.git/ee-franken-stack-staging-v1.tmp"
run_helper "$sync_failure_destination" > "$FIXTURE_ROOT/sync-resume.log" 2>&1
assert_clean_materialization "$sync_failure_destination"
assert_absent "$sync_failure_destination/.ee-franken-stack-staging"

concurrency_destination=$(fresh_destination concurrency)
EE_FIXTURE_FAIL_REPO=''
EE_FIXTURE_FAIL_ONCE=''
EE_FIXTURE_SYNC_FAIL_ONCE=''
EE_FIXTURE_FETCH_DELAY='1'
EE_FIXTURE_FETCH_LOG="$FIXTURE_ROOT/concurrency.fetches"
: > "$EE_FIXTURE_FETCH_LOG"
run_helper "$concurrency_destination" > "$FIXTURE_ROOT/concurrency-1.log" 2>&1 &
concurrency_pid_one=$!
sleep 0.1
run_helper "$concurrency_destination" > "$FIXTURE_ROOT/concurrency-2.log" 2>&1 &
concurrency_pid_two=$!
wait "$concurrency_pid_one"
wait "$concurrency_pid_two"
assert_clean_materialization "$concurrency_destination"
grep -F 'reuse asupersync@' "$FIXTURE_ROOT/concurrency-2.log" >/dev/null
[ "$(wc -l < "$EE_FIXTURE_FETCH_LOG")" -eq 7 ]
EE_FIXTURE_FETCH_DELAY=''
EE_FIXTURE_FETCH_LOG=''

symlink_parent="$FIXTURE_ROOT/symlink-parent"
symlink_target="$FIXTURE_ROOT/symlink-target"
mkdir "$symlink_target"
ln -s "$symlink_target" "$symlink_parent"
set +e
run_helper "$symlink_parent/child" > "$FIXTURE_ROOT/symlink.log" 2>&1
symlink_status=$?
set -e
[ "$symlink_status" -ne 0 ]
assert_absent "$symlink_target/child"
grep -F 'is a symlink; refusing to modify it' "$FIXTURE_ROOT/symlink.log" >/dev/null

staging_symlink_destination=$(fresh_destination staging-symlink)
staging_symlink_target="$FIXTURE_ROOT/staging-symlink-target"
mkdir "$staging_symlink_target"
ln -s "$staging_symlink_target" "$staging_symlink_destination/.ee-franken-stack-staging"
set +e
run_helper "$staging_symlink_destination" > "$FIXTURE_ROOT/staging-symlink.log" 2>&1
staging_symlink_status=$?
set -e
[ "$staging_symlink_status" -ne 0 ]
assert_absent "$staging_symlink_target/asupersync"
grep -F 'is a symlink; refusing to inspect it' "$FIXTURE_ROOT/staging-symlink.log" >/dev/null

# Build two fixture-only manifest revisions to pin the Cargo 0.0.x boundary.
sed -i 's/^version = "[^"]*"/version = "0.0.11"/' "$WORK_ROOT/asupersync/Cargo.toml"
git -C "$WORK_ROOT/asupersync" commit -qam 'fixture asupersync 0.0.11'
git -C "$WORK_ROOT/asupersync" push -q origin HEAD:refs/heads/main
ZERO_BAD_ASU=$(git -C "$WORK_ROOT/asupersync" rev-parse HEAD)
sed -i 's/version = "0\.4\.9"/version = "0.0.9"/' "$WORK_ROOT/sqlmodel_rust/Cargo.toml"
git -C "$WORK_ROOT/sqlmodel_rust" commit -qam 'fixture SQLModel 0.0.9 requirement'
git -C "$WORK_ROOT/sqlmodel_rust" push -q origin HEAD:refs/heads/main
ZERO_SQLMODEL=$(git -C "$WORK_ROOT/sqlmodel_rust" rev-parse HEAD)

ZERO_SOURCE="$FIXTURE_ROOT/zero-source"
mkdir -p "$ZERO_SOURCE/scripts"
cp "$CHECKOUT_SCRIPT" "$ZERO_SOURCE/scripts/checkout-franken-stack.sh"
chmod +x "$ZERO_SOURCE/scripts/checkout-franken-stack.sh"
write_lock "$ZERO_SOURCE/franken-stack.lock" "$ZERO_BAD_ASU" "$ZERO_SQLMODEL"
ACTIVE_SOURCE_ROOT="$ZERO_SOURCE"
EXPECTED_REV_ASUPERSYNC="$ZERO_BAD_ASU"
EXPECTED_REV_SQLMODEL="$ZERO_SQLMODEL"
ZERO_BAD_DEST=$(fresh_destination zero-bad)
ZERO_BAD_MANIFEST_HASH=$(sha256sum "$WORK_ROOT/sqlmodel_rust/Cargo.toml" | awk '{ print $1 }')
set +e
run_helper "$ZERO_BAD_DEST" > "$FIXTURE_ROOT/zero-bad.log" 2>&1
zero_bad_status=$?
set -e
[ "$zero_bad_status" -ne 0 ]
grep -F 'requirement 0.0.9 is incompatible with asupersync 0.0.11' "$FIXTURE_ROOT/zero-bad.log" >/dev/null
[ "$ZERO_BAD_MANIFEST_HASH" = "$(sha256sum "$WORK_ROOT/sqlmodel_rust/Cargo.toml" | awk '{ print $1 }')" ]
for repository in \
  asupersync \
  franken_agent_detection \
  franken_networkx \
  frankensearch \
  frankensqlite \
  sqlmodel_rust \
  toon_rust
do
  assert_absent "$ZERO_BAD_DEST/$repository"
done
assert_absent "$ZERO_BAD_DEST/.ee-franken-stack-staging"

sed -i 's/version = "0\.0\.11"/version = "0.0.9"/' "$WORK_ROOT/asupersync/Cargo.toml"
git -C "$WORK_ROOT/asupersync" commit -qam 'fixture asupersync 0.0.9'
git -C "$WORK_ROOT/asupersync" push -q origin HEAD:refs/heads/main
ZERO_GOOD_ASU=$(git -C "$WORK_ROOT/asupersync" rev-parse HEAD)
write_lock "$ZERO_SOURCE/franken-stack.lock" "$ZERO_GOOD_ASU" "$ZERO_SQLMODEL"
EXPECTED_REV_ASUPERSYNC="$ZERO_GOOD_ASU"
ZERO_GOOD_DEST=$(fresh_destination zero-good)
run_helper "$ZERO_GOOD_DEST" > "$FIXTURE_ROOT/zero-good.log" 2>&1
assert_clean_materialization "$ZERO_GOOD_DEST"
grep -F 'verified SQLModel asupersync requirement 0.0.9 against 0.0.9' "$FIXTURE_ROOT/zero-good.log" >/dev/null

printf 'checkout-franken-stack fixture tests passed\n'
