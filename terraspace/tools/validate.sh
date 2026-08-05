#!/usr/bin/env bash
# Static validation of every module and stack, without Terraspace and without
# touching a cloud account.
#
# Terraspace normally injects config/terraform/provider.tf into each built
# stack, so a stack directory on its own has no required_providers block and
# `terraform validate` would refuse to run. This script reproduces that build
# step in a scratch copy:
#
#   1. copy app/ to a temp tree so the ../../modules/ paths keep resolving
#   2. drop provider.tf into every stack and module
#   3. remove the ERB tfvars, which are not valid HCL until rendered
#   4. terraform init -backend=false && terraform validate
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

cp -R "$ROOT/app" "$WORK/app"

# ERB templates are not HCL; terraform must never see them.
find "$WORK/app" -type d -name tfvars -exec rm -rf {} + 2>/dev/null

targets=()
if [[ $# -gt 0 ]]; then
  for name in "$@"; do
    for d in "$WORK/app/stacks/$name" "$WORK/app/modules/$name"; do
      [[ -d "$d" ]] && targets+=("$d")
    done
  done
else
  for d in "$WORK"/app/modules/* "$WORK"/app/stacks/*; do
    [[ -d "$d" ]] && targets+=("$d")
  done
fi

# Modules carry their own versions.tf; stacks get the shared provider block
# that Terraspace would have copied in.
for d in "${targets[@]}"; do
  if [[ ! -f "$d/versions.tf" ]]; then
    cp "$ROOT/config/terraform/provider.tf" "$d/provider.tf"
  fi
done

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
