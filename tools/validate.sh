#!/usr/bin/env bash
# Static validation of every module and stack, without touching a cloud account.
#
# Each stack references shared modules with `source = "../../modules/..."`.
# We build a scratch tree that mirrors the project root so those relative paths
# keep resolving, then run `terraform init -backend=false && terraform validate`.
#
# Usage:  tools/validate.sh [stack-or-module-name ...]

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/cis-validate.XXXXXX")"
CACHE="${TF_PLUGIN_CACHE_DIR:-$HOME/.terraform.d/plugin-cache}"

mkdir -p "$CACHE"
export TF_PLUGIN_CACHE_DIR="$CACHE"
export TF_IN_AUTOMATION=1

cleanup() { [[ -n "${KEEP_WORKDIR:-}" ]] || rm -rf "$WORK"; }
trap cleanup EXIT

# Re-create the project-root-relative layout that module source paths expect.
mkdir -p "$WORK/project"
cp -R "$ROOT/cis_cloud/data/stacks" "$WORK/project/stacks"
cp -R "$ROOT/cis_cloud/data/modules" "$WORK/project/modules"

STACK_ROOT="$WORK/project/stacks"
MODULE_ROOT="$WORK/project/modules"

targets=()
if [[ $# -gt 0 ]]; then
  # A name may be a stack ("storage"), a cloud-qualified stack ("aws/storage")
  # or a module ("security_group_baseline").
  for name in "$@"; do
    for d in "$STACK_ROOT/$name" "$MODULE_ROOT/$name"; do
      [[ -d "$d" ]] && targets+=("$d")
    done
  done
else
  # Modules are one level deep; stacks are stacks/<name> (tencent) or
  # stacks/<cloud>/<name> (later clouds). Find every directory holding .tf.
  for d in "$MODULE_ROOT"/*; do
    [[ -d "$d" ]] && targets+=("$d")
  done
  while IFS= read -r d; do
    targets+=("$d")
  done < <(find "$STACK_ROOT" -type d -name .terraform -prune -o -type f -name '*.tf' -print \
            | xargs -n1 dirname | sort -u)
fi

failed=0
for d in "${targets[@]}"; do
  name="$(basename "$(dirname "$d")")/$(basename "$d")"
  printf '%-40s ' "$name"

  if ! out=$(terraform -chdir="$d" init -backend=false -input=false -no-color 2>&1); then
    echo "INIT FAILED"
    echo "$out" | sed 's/^/    /'
    failed=1
    continue
  fi

  if out=$(terraform -chdir="$d" validate -no-color 2>&1); then
    echo "ok"
  else
    echo "INVALID"
    echo "$out" | sed 's/^/    /'
    failed=1
  fi
done

if [[ $failed -eq 0 ]]; then
  echo
  echo "all modules and stacks validate"
else
  echo
  echo "validation failed"
fi
exit $failed
