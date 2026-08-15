"""Port of test/{aws,azure,gcp,alibaba}_wiring_test.rb — multi-cloud registry <-> HCL."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import cis_cloud as C
from cis_cloud.catalog import Catalog
from hcl_utils import object_keys, read, string_list, top_blocks

CLOUDS = ["aws", "azure", "gcp", "alibaba"]


@pytest.fixture(params=CLOUDS)
def cloud(request):
    return request.param


def cloud_path(cloud, stack, *parts):
    return Path(C.get_root()) / "stacks" / cloud / stack / "/".join(parts)


def cloud_main(cloud, stack):
    return read(cloud_path(cloud, stack, "main.tf"))


def cloud_catalog(cloud):
    return Catalog.load(Path(C.get_root()) / "config" / cloud / "controls.yml")


def cloud_stacks(cloud):
    return [C.AUDIT_STACK] + C.HARDENING_STACKS[cloud]


def test_every_stack_exists_on_disk_with_the_expected_files(cloud):
    for stack in cloud_stacks(cloud):
        assert cloud_path(cloud, stack).is_dir(), f"missing {cloud} stack: {stack}"
        for f in ["variables.tf", "outputs.tf", "provider.tf", "backend.tf", "terraform.tfvars.example"]:
            assert cloud_path(cloud, stack, f).is_file(), f"{stack}: no {f}"


def test_audit_has_assessment_logic(cloud):
    assert cloud_path(cloud, "audit", "data.tf").is_file(), "audit: no data.tf"
    assert cloud_path(cloud, "audit", "checks.tf").is_file(), "audit: no checks.tf"


def test_each_cloud_stack_implements_exactly_what_the_registry_routes_to_it(cloud):
    cat = cloud_catalog(cloud)
    for stack in C.HARDENING_STACKS[cloud]:
        implemented = string_list(cloud_main(cloud, stack), "implemented")
        assert implemented is not None, f"{stack}: main.tf has no local.implemented"
        expected = [c.id for c in cat.controls if c.remediable() and c.stack == stack]
        assert sorted(implemented) == sorted(expected), (
            f"{cloud}/{stack}: registry says {sorted(expected)} "
            f"but main.tf implements {sorted(implemented)}"
        )


def test_no_cloud_control_is_implemented_by_two_stacks(cloud):
    cat = cloud_catalog(cloud)
    seen = {}
    for stack in C.HARDENING_STACKS[cloud]:
        for cid in string_list(cloud_main(cloud, stack), "implemented"):
            assert cid not in seen, f"{cid} is implemented by both {seen[cid]} and {stack}"
            seen[cid] = stack
    assert len(seen) == len([c for c in cat.controls if c.remediable()])


def test_cloud_implemented_lists_are_sorted_and_free_of_duplicates(cloud):
    for stack in C.HARDENING_STACKS[cloud]:
        ids = string_list(cloud_main(cloud, stack), "implemented")
        assert ids == list(dict.fromkeys(ids)), f"{stack}: duplicate id in local.implemented"
        assert ids == sorted(ids, key=lambda i: [int(p) for p in i.split(".")]), \
            f"{stack}: local.implemented is out of order"


def test_every_cloud_control_id_mentioned_in_hcl_exists_in_the_registry(cloud):
    known = set(cloud_catalog(cloud).ids)
    for path in sorted((Path(C.get_root()) / "stacks" / cloud).rglob("*.tf")):
        src = re.sub(r'\bversion\s*=\s*"[^"]*"', "", read(path))
        for cid in sorted(set(re.findall(r'"(\d+\.\d+)"', src))):
            assert cid in known, (
                f"{path.relative_to(C.get_root())} references {cid}, which is not in config/{cloud}/controls.yml"
            )


def test_each_cloud_stack_asserts_its_own_alignment_at_plan_time(cloud):
    for stack in C.HARDENING_STACKS[cloud]:
        names = [b["labels"][0] for b in top_blocks(cloud_main(cloud, stack)) if b["type"] == "check" and b["labels"]]
        assert "cis_registry_alignment" in names, f"{stack}: no alignment check block"
        assert "cis_targets_present" in names, f"{stack}: nothing warns on empty inventory"


def test_every_cloud_stack_accepts_enabled_controls(cloud):
    for stack in cloud_stacks(cloud):
        vars_ = [b["labels"][0] for b in top_blocks(read(cloud_path(cloud, stack, "variables.tf")))
                 if b["type"] == "variable" and b["labels"]]
        assert "enabled_controls" in vars_, f"{stack}: cannot be filtered"


def test_every_cloud_stack_has_terraform_tfvars_example(cloud):
    for stack in cloud_stacks(cloud):
        assert cloud_path(cloud, stack, "terraform.tfvars.example").is_file(), \
            f"{stack}: no terraform.tfvars.example"


def test_every_cloud_resource_and_module_is_gated_on_a_selected_control(cloud):
    from test_wiring import gated_locals

    for stack in C.HARDENING_STACKS[cloud]:
        src = cloud_main(cloud, stack)
        gated = gated_locals(src)
        blocks = [b for b in top_blocks(src) if b["type"] in ("resource", "module")]
        assert blocks, f"{stack}: implements controls but declares nothing"

        # for_each may forward to a data source that is itself gated on the
        # selection (e.g. aws_s3_bucket_policy over the deny_http documents).
        data_gates = {}
        for b in top_blocks(src):
            if b["type"] == "data":
                meta = re.search(r"^\s*(count|for_each)\s*=.*$", b["body"], re.MULTILINE)
                data_gates[".".join(b["labels"])] = meta.group(0) if meta else ""

        for b in blocks:
            label = f"{stack}: {b['type']} {'.'.join(b['labels'])}"
            meta = re.search(r"^\s*(count|for_each)\s*=.*$", b["body"], re.MULTILINE)
            assert meta, f"{label} has neither count nor for_each - it would be created unconditionally"

            locals_ref = re.findall(r"local\.([a-zA-Z0-9_]+)", meta.group(0))
            data_ref = re.findall(r"data\.([a-zA-Z0-9_.]+)", meta.group(0))
            via_data = any(
                (gate := data_gates.get(d))
                and ("var.enabled_controls" in gate
                     or any(n in gated for n in re.findall(r"local\.([a-zA-Z0-9_]+)", gate)))
                for d in data_ref
            )
            assert any(name in gated for name in locals_ref) \
                or "var.enabled_controls" in meta.group(0) \
                or via_data, \
                f"{label} is gated on {meta.group(0).strip()!r}, which does not depend on the selection"


def test_the_cloud_audit_stack_declares_no_managed_resources(cloud):
    for path in (Path(C.get_root()) / "stacks" / cloud / "audit").glob("*.tf"):
        types = [b["type"] for b in top_blocks(read(path))]
        assert "resource" not in types, f"{path.name}: `scan` must never be able to change anything"
        assert "module" not in types, f"{path.name}: a module could hide a resource"


def test_the_cloud_audit_stack_probes_exactly_the_detectable_controls(cloud):
    cat = cloud_catalog(cloud)
    src = read(cloud_path(cloud, "audit", "checks.tf"))
    probed = list(object_keys(src, "violation_probes") or []) + list(object_keys(src, "presence_probes") or [])
    expected = [c.id for c in cat.controls if c.detectable()]
    assert sorted(probed) == sorted(expected), (
        f"registry marks {sorted(set(expected) - set(probed))} detectable with no probe; "
        f"probes exist for {sorted(set(probed) - set(expected))} which the registry does not"
    )


def test_each_cloud_control_is_probed_once(cloud):
    src = read(cloud_path(cloud, "audit", "checks.tf"))
    violation = object_keys(src, "violation_probes") or []
    presence = object_keys(src, "presence_probes") or []
    assert not (set(violation) & set(presence)), "a control with two probes gets two verdicts"
    assert violation == list(dict.fromkeys(violation))
    assert presence == list(dict.fromkeys(presence))


def test_cloud_audit_data_sources_are_gated(cloud):
    src = read(cloud_path(cloud, "audit", "data.tf"))
    for b in top_blocks(src):
        if b["type"] == "data":
            meta = re.search(r"^\s*(count|for_each)\s*=.*$", b["body"], re.MULTILINE)
            assert meta, f"data {'.'.join(b['labels'])} always queries, even when unselected"


def test_cloud_audit_findings_are_filtered_by_the_selection(cloud):
    src = read(cloud_path(cloud, "audit", "checks.tf"))
    assert re.search(r"findings\s*=\s*\{.*contains\(var\.enabled_controls, id\)", src, re.DOTALL), \
        "the audit stack must only report on what was selected"


def test_every_cloud_hardening_stack_reports_what_it_did(cloud):
    for stack in C.HARDENING_STACKS[cloud]:
        outs = [b["labels"][0] for b in top_blocks(read(cloud_path(cloud, stack, "outputs.tf")))
                if b["type"] == "output" and b["labels"]]
        assert "cis_applied" in outs, f"{stack}: no cis_applied output"
        assert "cis_implemented" in outs, f"{stack}: no cis_implemented output"


def test_the_cloud_audit_stack_emits_the_output_the_cli_reads_back(cloud):
    outs = read(cloud_path(cloud, "audit", "outputs.tf"))
    assert 'output "cis_findings"' in outs
    assert 'output "cis_summary"' in outs
