# frozen_string_literal: true

require_relative "test_helper"

# The registry and the Terraform code are two halves of one claim: "this
# toolkit enforces control X". If they drift apart, `cis apply` reports success
# for a control nothing implements, which is the worst failure mode a
# compliance tool has. These tests hold the two halves against each other.
class WiringTest < CisTestCase
  include CisTest::Hcl

  ALL_STACKS = ([Cis::AUDIT_STACK] + Cis::HARDENING_STACKS).freeze
  MODULES    = %w[security_group_baseline cos_secure_bucket cls_audit_alarm].freeze

  def main(stack)
    Hcl.read(CisTest.stack_path(stack, "main.tf"))
  end

  # ---- layout -------------------------------------------------------------

  def test_every_declared_stack_exists_on_disk
    ALL_STACKS.each do |stack|
      assert File.directory?(CisTest.stack_path(stack)), "missing stack: #{stack}"
      assert File.file?(CisTest.stack_path(stack, "variables.tf")), "#{stack}: no variables.tf"
      assert File.file?(CisTest.stack_path(stack, "outputs.tf")), "#{stack}: no outputs.tf"
    end
  end

  def test_there_are_no_stray_stacks
    on_disk = Dir.children(File.join(Cis::ROOT, "app", "stacks")).sort
    assert_equal ALL_STACKS.sort, on_disk,
                 "a stack on disk that the toolkit does not know about will never run"
  end

  def test_every_module_is_self_describing
    MODULES.each do |mod|
      %w[main.tf variables.tf outputs.tf versions.tf].each do |f|
        assert File.file?(CisTest.module_path(mod, f)), "#{mod}: no #{f}"
      end
    end
  end

  # ---- the registry <-> HCL contract --------------------------------------

  def test_each_hardening_stack_implements_exactly_what_the_registry_routes_to_it
    hardening_stacks.each do |stack|
      implemented = Hcl.string_list(main(stack), "implemented")
      refute_nil implemented, "#{stack}: main.tf has no local.implemented"

      expected = catalog.controls.select { |c| c.remediable? && c.stack == stack }.map(&:id)

      assert_equal expected.sort, implemented.sort,
                   "#{stack}: registry says #{expected.sort.join(', ')} " \
                   "but main.tf implements #{implemented.sort.join(', ')}"
    end
  end

  def test_no_control_is_implemented_by_two_stacks
    seen = {}
    hardening_stacks.each do |stack|
      Hcl.string_list(main(stack), "implemented").each do |id|
        refute seen[id], "#{id} is implemented by both #{seen[id]} and #{stack}"
        seen[id] = stack
      end
    end
    assert_equal catalog.controls.count(&:remediable?), seen.size
  end

  def test_implemented_lists_are_sorted_and_free_of_duplicates
    hardening_stacks.each do |stack|
      ids = Hcl.string_list(main(stack), "implemented")
      assert_equal ids.uniq, ids, "#{stack}: duplicate id in local.implemented"
      assert_equal ids.sort_by { |i| i.split(".").map(&:to_i) }, ids,
                   "#{stack}: local.implemented is out of order"
    end
  end

  def test_every_control_id_mentioned_in_hcl_exists_in_the_registry
    known = catalog.ids
    Dir.glob(File.join(Cis::ROOT, "app", "**", "*.tf")).sort.each do |path|
      # `version = "2.0"` is a COS policy-language version, not a control.
      src = Hcl.read(path).gsub(/\bversion\s*=\s*"[^"]*"/, "")
      src.scan(/"(\d+\.\d+)"/).flatten.uniq.each do |id|
        assert_includes known, id,
                        "#{path.sub("#{Cis::ROOT}/", '')} references #{id}, " \
                        "which is not in config/controls.yml"
      end
    end
  end

  def test_each_stack_asserts_its_own_alignment_at_plan_time
    # A run-time guard for the case the test suite is not run: if controls.yml
    # routes something a stack cannot do, terraform itself must say so.
    hardening_stacks.each do |stack|
      names = Hcl.top_blocks(main(stack)).select { |b| b[:type] == "check" }.map { |b| b[:labels].first }
      assert_includes names, "cis_registry_alignment", "#{stack}: no alignment check block"
      assert_includes names, "cis_targets_present",
                      "#{stack}: nothing warns the operator when the inventory is empty"
    end
  end

  # ---- filtering reaches Terraform ----------------------------------------

  def test_every_stack_accepts_enabled_controls
    ALL_STACKS.each do |stack|
      vars = Hcl.top_blocks(Hcl.read(CisTest.stack_path(stack, "variables.tf")))
                .select { |b| b[:type] == "variable" }.map { |b| b[:labels].first }
      assert_includes vars, "enabled_controls", "#{stack}: cannot be filtered"
    end
  end

  def test_every_stack_renders_its_enabled_controls_from_the_registry
    hardening_stacks.each do |stack|
      tfvars = Hcl.read(CisTest.stack_path(stack, "tfvars", "base.tfvars"))
      assert_match(/enabled_controls\s*=\s*<%=\s*Cis\.controls_for_stack\("#{stack}"\)\.to_json\s*%>/,
                   tfvars, "#{stack}: tfvars does not wire enabled_controls to the selector")
    end

    audit = Hcl.read(CisTest.stack_path(Cis::AUDIT_STACK, "tfvars", "base.tfvars"))
    assert_match(/enabled_controls\s*=\s*<%=\s*Cis\.controls_for_audit\.to_json\s*%>/, audit,
                 "audit: without this the scan silently assesses nothing")
  end

  def test_the_erb_in_tfvars_only_calls_methods_that_exist
    Dir.glob(File.join(Cis::ROOT, "app", "stacks", "*", "tfvars", "*.tfvars")).each do |path|
      File.read(path).scan(/<%=\s*Cis\.([a-z_]+)/).flatten.uniq.each do |meth|
        assert_respond_to Cis, meth, "#{File.basename(File.dirname(File.dirname(path)))}: Cis.#{meth} does not exist"
      end
    end
  end

  def test_every_hardening_stack_has_tfvars
    hardening_stacks.each do |stack|
      assert File.file?(CisTest.stack_path(stack, "tfvars", "base.tfvars")),
             "#{stack}: no tfvars means the stack runs with default (empty) inputs"
    end
  end

  # ---- gating: nothing is written unless a control asked for it -----------

  def test_every_resource_and_module_is_gated_on_a_selected_control
    hardening_stacks.each do |stack|
      src    = main(stack)
      gated  = gated_locals(src)
      blocks = Hcl.top_blocks(src).select { |b| %w[resource module].include?(b[:type]) }

      refute_empty blocks, "#{stack}: implements controls but declares nothing"

      blocks.each do |b|
        label = "#{stack}: #{b[:type]} #{b[:labels].join('.')}"
        meta  = b[:body][/^\s*(count|for_each)\s*=.*$/]
        refute_nil meta, "#{label} has neither count nor for_each - it would be created unconditionally"

        referenced = meta.scan(/local\.([a-zA-Z0-9_]+)/).flatten
        assert referenced.any? { |name| gated.include?(name) } ||
               meta.include?("var.enabled_controls"),
               "#{label} is gated on #{meta.strip.inspect}, which does not depend on the selection"
      end
    end
  end

  # Locals that transitively depend on var.enabled_controls.
  def gated_locals(src)
    locals = Hcl.locals_map(src)
    gated  = Set.new

    loop do
      before = gated.size
      locals.each do |name, expr|
        next if gated.include?(name)
        next unless expr.include?("var.enabled_controls") ||
                    gated.any? { |g| expr =~ /local\.#{Regexp.escape(g)}\b/ }
        gated << name
      end
      break if gated.size == before
    end

    refute_empty gated, "no local depends on var.enabled_controls - the stack cannot be filtered"
    gated
  end

  # ---- the audit stack is genuinely read-only -----------------------------

  def test_the_audit_stack_declares_no_managed_resources
    Dir.glob(CisTest.stack_path(Cis::AUDIT_STACK, "*.tf")).each do |path|
      types = Hcl.top_blocks(Hcl.read(path)).map { |b| b[:type] }
      refute_includes types, "resource",
                      "#{File.basename(path)}: `cis scan` must never be able to change anything"
      refute_includes types, "module", "#{File.basename(path)}: a module could hide a resource"
    end
  end

  def test_the_audit_stack_probes_exactly_the_detectable_controls
    src      = Hcl.read(CisTest.stack_path(Cis::AUDIT_STACK, "checks.tf"))
    probed   = Hcl.object_keys(src, "violation_probes") + Hcl.object_keys(src, "presence_probes")
    expected = catalog.controls.select(&:detectable?).map(&:id)

    assert_equal expected.sort, probed.sort,
                 "registry marks #{(expected - probed).join(', ')} detectable with no probe; " \
                 "probes exist for #{(probed - expected).join(', ')} which the registry does not"
  end

  def test_each_control_is_probed_once
    src = Hcl.read(CisTest.stack_path(Cis::AUDIT_STACK, "checks.tf"))
    violation = Hcl.object_keys(src, "violation_probes")
    presence  = Hcl.object_keys(src, "presence_probes")
    assert_empty violation & presence, "a control with two probes gets two verdicts"
    assert_equal violation.uniq, violation
    assert_equal presence.uniq, presence
  end

  def test_audit_data_sources_are_gated_so_a_narrow_scan_calls_narrow_apis
    src = Hcl.read(CisTest.stack_path(Cis::AUDIT_STACK, "data.tf"))
    Hcl.top_blocks(src).select { |b| b[:type] == "data" }.each do |b|
      meta = b[:body][/^\s*(count|for_each)\s*=.*$/]
      refute_nil meta, "data #{b[:labels].join('.')} always queries, even when unselected"
    end
  end

  def test_audit_findings_are_filtered_by_the_selection
    src = Hcl.read(CisTest.stack_path(Cis::AUDIT_STACK, "checks.tf"))
    assert_match(/findings\s*=\s*\{.*contains\(var\.enabled_controls, id\)/m, src,
                 "the audit stack must only report on what was selected")
  end

  # ---- outputs ------------------------------------------------------------

  def test_every_hardening_stack_reports_what_it_did
    hardening_stacks.each do |stack|
      outs = Hcl.top_blocks(Hcl.read(CisTest.stack_path(stack, "outputs.tf")))
                .select { |b| b[:type] == "output" }.map { |b| b[:labels].first }
      assert_includes outs, "cis_applied", "#{stack}: no cis_applied output"
      assert_includes outs, "cis_implemented", "#{stack}: no cis_implemented output"
    end
  end

  def test_a_stack_that_can_fall_short_says_so
    # If main.tf computes local.unreachable, that honesty has to reach the
    # operator through an output, not just an error message.
    hardening_stacks.each do |stack|
      next unless Hcl.locals_map(main(stack)).key?("unreachable")
      outs = Hcl.read(CisTest.stack_path(stack, "outputs.tf"))
      assert_match(/output "unreachable_controls"/, outs,
                   "#{stack}: computes local.unreachable but never exports it")
    end
  end

  def test_the_audit_stack_emits_the_output_the_cli_reads_back
    outs = Hcl.read(CisTest.stack_path(Cis::AUDIT_STACK, "outputs.tf"))
    assert_match(/output "cis_findings"/, outs,
                 "Runner#read_findings looks for cis_findings by name")
    assert_match(/output "cis_summary"/, outs)
  end

  # ---- provider plumbing --------------------------------------------------

  def test_the_provider_is_pinned
    src = Hcl.read(File.join(Cis::ROOT, "config", "terraform", "provider.tf"))
    assert_match(%r{tencentcloudstack/tencentcloud}, src)
    assert_match(/version\s*=\s*"[~>=\s]*\d+\.\d+/, src, "the provider version must be pinned")
  end

  def test_modules_declare_their_own_requirements
    MODULES.each do |mod|
      src = Hcl.read(CisTest.module_path(mod, "versions.tf"))
      assert_match(%r{tencentcloudstack/tencentcloud}, src, "#{mod}: no provider requirement")
    end
  end

  def test_stacks_do_not_redeclare_the_provider
    # config/terraform/provider.tf is injected into every stack by Terraspace;
    # a second declaration is a duplicate-provider error at init time.
    hardening_stacks.each do |stack|
      refute File.exist?(CisTest.stack_path(stack, "versions.tf")),
             "#{stack}: versions.tf collides with config/terraform/provider.tf"
    end
  end

  # ---- formatting ---------------------------------------------------------

  def test_hcl_is_canonically_formatted
    skip "terraform not on PATH" unless system("command -v terraform > /dev/null 2>&1")

    # Never point terraform at tfvars/: those files contain ERB and are not
    # valid HCL until Terraspace renders them.
    dirs = [File.join(Cis::ROOT, "config", "terraform")] +
           MODULES.map { |m| CisTest.module_path(m) } +
           ALL_STACKS.map { |s| CisTest.stack_path(s) }

    offenders = dirs.reject do |dir|
      _out, _err, st = Open3.capture3("terraform", "fmt", "-check", "-list=false", dir)
      st.success?
    end

    assert_empty offenders.map { |d| d.sub("#{Cis::ROOT}/", "") },
                 "run `terraform fmt` on these directories"
  end
end
