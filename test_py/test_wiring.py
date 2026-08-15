"""Port of test/wiring_test.rb — registry <-> HCL contract for tencent."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import cis_cloud as C
from conftest import module_path, stack_path
from hcl_utils import locals_map, object_keys, read, string_list, top_blocks

ALL_STACKS = [C.AUDIT_STACK] + C.hardening_stacks()
MODULES = ["security_group_baseline", "cos_secure_bucket", "cls_audit_alarm"]


def main(stack):
    return read(stack_path(stack, "main.tf"))


def test_every_declared_stack_exists_on_disk():
    for stack in ALL_STACKS:
        assert stack_path(stack).is_dir(), f"missing stack: {stack}"
        assert stack_path(stack, "variables.tf").is_file(), f"{stack}: no variables.tf"
        assert stack_path(stack, "outputs.tf").is_file(), f"{stack}: no outputs.tf"


def test_there_are_no_stray_stacks():
    cloud_dirs = [c for c in (C.IMPLEMENTED_CLOUDS + C.REFERENCE_CLOUDS) if c != "tencent"]
    on_disk = sorted(
        p.name for p in (C.get_root() / "stacks").iterdir() if p.is_dir()
    )
    on_disk = [d for d in on_disk if d not in cloud_dirs]
    assert on_disk == sorted(ALL_STACKS), "a stack on disk that cis does not know about will never run"


def test_every_module_is_self_describing():
    for mod in MODULES:
        for f in ["main.tf", "variables.tf", "outputs.tf", "versions.tf"]:
            assert module_path(mod, f).is_file(), f"{mod}: no {f}"


def test_each_hardening_stack_implements_exactly_what_the_registry_routes_to_it(catalog):
    for stack in C.hardening_stacks():
        implemented = string_list(main(stack), "implemented")
        assert implemented is not None, f"{stack}: main.tf has no local.implemented"
        expected = [c.id for c in catalog.controls if c.remediable() and c.stack == stack]
        assert sorted(implemented) == sorted(expected), (
            f"{stack}: registry says {sorted(expected)} "
            f"but main.tf implements {sorted(implemented)}"
        )


def test_no_control_is_implemented_by_two_stacks(catalog):
    seen = {}
    for stack in C.hardening_stacks():
        for cid in string_list(main(stack), "implemented"):
            assert cid not in seen, f"{cid} is implemented by both {seen[cid]} and {stack}"
            seen[cid] = stack
    assert len(seen) == len([c for c in catalog.controls if c.remediable()])


def test_implemented_lists_are_sorted_and_free_of_duplicates():
    for stack in C.hardening_stacks():
        ids = string_list(main(stack), "implemented")
        assert ids == list(dict.fromkeys(ids)), f"{stack}: duplicate id in local.implemented"
        keyed = sorted(ids, key=lambda i: [int(p) for p in i.split(".")])
        assert ids == keyed, f"{stack}: local.implemented is out of order"


def test_every_control_id_mentioned_in_hcl_exists_in_the_registry(catalog):
    known = set(catalog.ids)
    cloud_dirs = [c for c in (C.IMPLEMENTED_CLOUDS + C.REFERENCE_CLOUDS) if c != "tencent"]
    for path in sorted((C.get_root() / "stacks").rglob("*.tf")):
        if any(f"/stacks/{d}/" in str(path) for d in cloud_dirs):
            continue
        src = read(path)
        src = re_sub_version(src)
        for cid in sorted(set(re.findall(r'"(\d+\.\d+)"', src))):
            assert cid in known, (
                f"{path.relative_to(C.get_root())} references {cid}, "
                f"which is not in config/controls.yml"
            )


def test_each_stack_asserts_its_own_alignment_at_plan_time():
    for stack in C.hardening_stacks():
        names = [b["labels"][0] for b in top_blocks(main(stack)) if b["type"] == "check" and b["labels"]]
        assert "cis_registry_alignment" in names, f"{stack}: no alignment check block"
        assert "cis_targets_present" in names, f"{stack}: nothing warns the operator when the inventory is empty"


def test_every_stack_accepts_enabled_controls():
    for stack in ALL_STACKS:
        vars_ = [b["labels"][0] for b in top_blocks(read(stack_path(stack, "variables.tf")))
                 if b["type"] == "variable" and b["labels"]]
        assert "enabled_controls" in vars_, f"{stack}: cannot be filtered"


def test_every_stack_has_terraform_tfvars_example():
    for stack in ALL_STACKS:
        assert stack_path(stack, "terraform.tfvars.example").is_file(), \
            f"{stack}: no terraform.tfvars.example"


def test_every_resource_and_module_is_gated_on_a_selected_control():
    for stack in C.hardening_stacks():
        src = main(stack)
        gated = gated_locals(src)
        blocks = [b for b in top_blocks(src) if b["type"] in ("resource", "module")]
        assert blocks, f"{stack}: implements controls but declares nothing"
        for b in blocks:
            label = f"{stack}: {b['type']} {'.'.join(b['labels'])}"
            meta = re.search(r"^\s*(count|for_each)\s*=.*$", b["body"], re.MULTILINE)
            assert meta, f"{label} has neither count nor for_each - it would be created unconditionally"
            referenced = re.findall(r"local\.([a-zA-Z0-9_]+)", meta.group(0))
            assert any(name in gated for name in referenced) or "var.enabled_controls" in meta.group(0), \
                f"{label} is gated on {meta.group(0).strip()!r}, which does not depend on the selection"


def gated_locals(src):
    locals_ = locals_map(src)
    gated = set()
    while True:
        before = len(gated)
        for name, expr in locals_.items():
            if name in gated:
                continue
            if "var.enabled_controls" in expr or any(
                re.search(rf"local\.{re.escape(g)}\b", expr) for g in gated
            ):
                gated.add(name)
        if len(gated) == before:
            break
    assert gated, "no local depends on var.enabled_controls - the stack cannot be filtered"
    return gated


def test_the_audit_stack_declares_no_managed_resources():
    for path in (C.get_root() / "stacks" / C.AUDIT_STACK).glob("*.tf"):
        types = [b["type"] for b in top_blocks(read(path))]
        assert "resource" not in types, f"{path.name}: `scan` must never be able to change anything"
        assert "module" not in types, f"{path.name}: a module could hide a resource"


def test_the_audit_stack_probes_exactly_the_detectable_controls(catalog):
    src = read(stack_path(C.AUDIT_STACK, "checks.tf"))
    probed = list(object_keys(src, "violation_probes") or []) + list(object_keys(src, "presence_probes") or [])
    expected = [c.id for c in catalog.controls if c.detectable()]
    assert sorted(probed) == sorted(expected), (
        f"registry marks {sorted(set(expected) - set(probed))} detectable with no probe; "
        f"probes exist for {sorted(set(probed) - set(expected))} which the registry does not"
    )


def test_each_control_is_probed_once(catalog):
    src = read(stack_path(C.AUDIT_STACK, "checks.tf"))
    violation = object_keys(src, "violation_probes") or []
    presence = object_keys(src, "presence_probes") or []
    assert not (set(violation) & set(presence)), "a control with two probes gets two verdicts"
    assert violation == list(dict.fromkeys(violation))
    assert presence == list(dict.fromkeys(presence))


def test_audit_data_sources_are_gated_so_a_narrow_scan_calls_narrow_apis():
    src = read(stack_path(C.AUDIT_STACK, "data.tf"))
    for b in top_blocks(src):
        if b["type"] == "data":
            meta = re.search(r"^\s*(count|for_each)\s*=.*$", b["body"], re.MULTILINE)
            assert meta, f"data {'.'.join(b['labels'])} always queries, even when unselected"


def test_audit_findings_are_filtered_by_the_selection():
    src = read(stack_path(C.AUDIT_STACK, "checks.tf"))
    assert re.search(r"findings\s*=\s*\{.*contains\(var\.enabled_controls, id\)", src, re.DOTALL), \
        "the audit stack must only report on what was selected"


def test_every_hardening_stack_reports_what_it_did():
    for stack in C.hardening_stacks():
        outs = [b["labels"][0] for b in top_blocks(read(stack_path(stack, "outputs.tf")))
                if b["type"] == "output" and b["labels"]]
        assert "cis_applied" in outs, f"{stack}: no cis_applied output"
        assert "cis_implemented" in outs, f"{stack}: no cis_implemented output"


def test_a_stack_that_can_fall_short_says_so():
    for stack in C.hardening_stacks():
        if "unreachable" not in locals_map(main(stack)):
            continue
        outs = read(stack_path(stack, "outputs.tf"))
        assert 'output "unreachable_controls"' in outs, \
            f"{stack}: computes local.unreachable but never exports it"


def test_the_audit_stack_emits_the_output_the_cli_reads_back():
    outs = read(stack_path(C.AUDIT_STACK, "outputs.tf"))
    assert 'output "cis_findings"' in outs, "Runner#read_findings looks for cis_findings by name"
    assert 'output "cis_summary"' in outs


def test_each_stack_has_its_own_provider_tf():
    for stack in ALL_STACKS:
        assert stack_path(stack, "provider.tf").is_file(), \
            f"{stack}: no provider.tf - each stack is a self-contained root module"


def test_the_provider_is_pinned():
    src = read(stack_path("audit", "provider.tf"))
    assert "tencentcloudstack/tencentcloud" in src
    assert re.search(r'version\s*=\s*"[~>=\s]*\d+\.\d+', src), "the provider version must be pinned"


def test_modules_declare_their_own_requirements():
    for mod in MODULES:
        src = read(module_path(mod, "versions.tf"))
        assert "tencentcloudstack/tencentcloud" in src, f"{mod}: no provider requirement"


def test_hcl_is_canonically_formatted():
    if not _which("terraform"):
        pytest.skip("terraform not on PATH")
    dirs = [module_path(m) for m in MODULES] + [stack_path(s) for s in ALL_STACKS]
    offenders = []
    for d in dirs:
        # `terraform fmt` (1.5.x) resolves a directory argument relative to a
        # fixed `../..` offset, so absolute paths fail with "No file or
        # directory". chdir into each dir and pass "." instead.
        proc = subprocess.run(["terraform", "fmt", "-check", "-list=false", "."],
                              capture_output=True, text=True, cwd=str(d))
        if proc.returncode != 0:
            offenders.append(str(d))
    assert not offenders, f"run `terraform fmt` on these directories: {offenders}"


def _which(cmd):
    import shutil

    return shutil.which(cmd) is not None


import re  # noqa: E402


def re_sub_version(src):
    return re.sub(r'\bversion\s*=\s*"[^"]*"', "", src)
