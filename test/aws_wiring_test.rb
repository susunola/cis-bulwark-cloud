# frozen_string_literal: true

require_relative "test_helper"

# The registry <-> HCL contract, applied to the AWS variant. Mirrors the
# checks WiringTest runs for tencent, against config/aws/controls.yml and
# stacks/aws/*. AWS has no shared modules, so the module checks are skipped.
class AwsWiringTest < CisTestCase
  include CisTest::Hcl

  AWS_STACKS = ([Cis::AUDIT_STACK] + Cis::HARDENING_STACKS.fetch("aws")).freeze

  def aws_path(stack, *parts)
    File.join(Cis::ROOT, "stacks", "aws", stack, *parts)
  end

  def aws_main(stack)
    Hcl.read(aws_path(stack, "main.tf"))
  end

  def aws_catalog
    @aws_catalog ||= Cis::Catalog.load(File.join(Cis::ROOT, "config", "aws", "controls.yml"))
  end

  # ---- layout -------------------------------------------------------------

  def test_every_aws_stack_exists_on_disk_with_the_expected_files
    AWS_STACKS.each do |stack|
      assert File.directory?(aws_path(stack)), "missing aws stack: #{stack}"
      %w[variables.tf outputs.tf provider.tf backend.tf terraform.tfvars.example].each do |f|
        assert File.file?(aws_path(stack, f)), "#{stack}: no #{f}"
      end
    end
  end

  def test_audit_has_assessment_logic
    assert File.file?(aws_path("audit", "data.tf")), "audit: no data.tf"
    assert File.file?(aws_path("audit", "checks.tf")), "audit: no checks.tf"
  end

  # ---- registry <-> HCL -----------------------------------------------------

  def test_each_aws_stack_implements_exactly_what_the_registry_routes_to_it
    Cis::HARDENING_STACKS.fetch("aws").each do |stack|
      implemented = Hcl.string_list(aws_main(stack), "implemented")
      refute_nil implemented, "#{stack}: main.tf has no local.implemented"

      expected = aws_catalog.controls.select { |c| c.remediable? && c.stack == stack }.map(&:id)

      assert_equal expected.sort, implemented.sort,
                   "#{stack}: registry says #{expected.sort.join(', ')} " \
                   "but main.tf implements #{implemented.sort.join(', ')}"
    end
  end

  def test_no_aws_control_is_implemented_by_two_stacks
    seen = {}
    Cis::HARDENING_STACKS.fetch("aws").each do |stack|
      Hcl.string_list(aws_main(stack), "implemented").each do |id|
        refute seen[id], "#{id} is implemented by both #{seen[id]} and #{stack}"
        seen[id] = stack
      end
    end
    assert_equal aws_catalog.controls.count(&:remediable?), seen.size
  end

  def test_aws_audit_stack_declares_no_managed_resources
    Dir.glob(aws_path("audit", "*.tf")).each do |path|
      types = Hcl.top_blocks(Hcl.read(path)).map { |b| b[:type] }
      refute_includes types, "resource",
                      "#{File.basename(path)}: `cis scan` must never be able to change anything"
      refute_includes types, "module", "#{File.basename(path)}: a module could hide a resource"
    end
  end

  def test_aws_audit_probes_exactly_the_detectable_controls
    src      = Hcl.read(aws_path("audit", "checks.tf"))
    probed   = Hcl.object_keys(src, "violation_probes") + Hcl.object_keys(src, "presence_probes")
    expected = aws_catalog.controls.select(&:detectable?).map(&:id)

    assert_equal expected.sort, probed.sort,
                 "registry marks #{(expected - probed).join(', ')} detectable with no probe; " \
                 "probes exist for #{(probed - expected).join(', ')} which the registry does not"
  end

  def test_aws_audit_data_sources_are_gated
    src = Hcl.read(aws_path("audit", "data.tf"))
    Hcl.top_blocks(src).select { |b| b[:type] == "data" }.each do |b|
      meta = b[:body][/^\s*(count|for_each)\s*=.*$/]
      refute_nil meta, "data #{b[:labels].join('.')} always queries, even when unselected"
    end
  end

  def test_aws_hardening_resources_are_gated_on_the_selection
    Cis::HARDENING_STACKS.fetch("aws").each do |stack|
      src    = aws_main(stack)
      gated  = gated_locals(src)
      blocks = Hcl.top_blocks(src).select { |b| b[:type] == "resource" }
      refute_empty blocks, "#{stack}: implements controls but declares nothing"

      # for_each may forward to a data source that is itself gated on the
      # selection (e.g. aws_s3_bucket_policy over the deny_http documents).
      data_gates = Hcl.top_blocks(src).select { |b| b[:type] == "data" }
                     .to_h { |b| [b[:labels].join("."), b[:body][/^\s*(count|for_each)\s*=.*$/] || ""] }

      blocks.each do |b|
        meta = b[:body][/^\s*(count|for_each)\s*=.*$/]
        refute_nil meta, "#{stack} #{b[:labels].join('.')}: no count/for_each - would be created unconditionally"

        locals_ref   = meta.scan(/local\.([a-zA-Z0-9_]+)/).flatten
        data_ref     = meta.scan(/data\.([a-zA-Z0-9_.]+)/).flatten
        via_data     = data_ref.any? do |d|
          gate = data_gates[d]
          gate && (gate.include?("var.enabled_controls") ||
                   gate.scan(/local\.([a-zA-Z0-9_]+)/).flatten.any? { |n| gated.include?(n) })
        end

        assert locals_ref.any? { |name| gated.include?(name) } ||
               meta.include?("var.enabled_controls") || via_data,
               "#{stack} #{b[:labels].join('.')} is gated on #{meta.strip.inspect}, " \
               "which does not depend on the selection"
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

  def test_each_aws_hardening_stack_has_alignment_and_inventory_checks
    Cis::HARDENING_STACKS.fetch("aws").each do |stack|
      names = Hcl.top_blocks(aws_main(stack)).select { |b| b[:type] == "check" }.map { |b| b[:labels].first }
      assert_includes names, "cis_registry_alignment", "#{stack}: no alignment check block"
      assert_includes names, "cis_targets_present", "#{stack}: no targets-present check block"
    end
  end

  def test_each_aws_hardening_stack_reports_what_it_did
    Cis::HARDENING_STACKS.fetch("aws").each do |stack|
      outs = Hcl.top_blocks(Hcl.read(aws_path(stack, "outputs.tf")))
                .select { |b| b[:type] == "output" }.map { |b| b[:labels].first }
      assert_includes outs, "cis_applied", "#{stack}: no cis_applied output"
      assert_includes outs, "cis_implemented", "#{stack}: no cis_implemented output"
    end
  end

  def test_the_aws_provider_is_pinned_in_every_stack
    AWS_STACKS.each do |stack|
      src = Hcl.read(aws_path(stack, "provider.tf"))
      assert_match(%r{hashicorp/aws}, src, "#{stack}: wrong provider")
      assert_match(/version\s*=\s*"[~>=\s]*\d+\.\d+/, src, "#{stack}: the provider version must be pinned")
    end
  end

  def test_aws_hcl_is_canonically_formatted
    skip "terraform not on PATH" unless system("command -v terraform > /dev/null 2>&1")

    offenders = AWS_STACKS.reject do |stack|
      _out, _err, st = Open3.capture3("terraform", "fmt", "-check", "-list=false", aws_path(stack))
      st.success?
    end

    assert_empty offenders.map { |d| d.sub("#{Cis::ROOT}/", "") },
                 "run `terraform fmt` on these directories"
  end

  def test_every_aws_control_id_mentioned_in_hcl_exists_in_the_registry
    known = aws_catalog.ids
    Dir.glob(File.join(Cis::ROOT, "stacks", "aws", "**", "*.tf")).sort.each do |path|
      src = Hcl.read(path).gsub(/\bversion\s*=\s*"[^"]*"/, "")
      src.scan(/"(\d+\.\d+)"/).flatten.uniq.each do |id|
        assert_includes known, id,
                        "#{path.sub("#{Cis::ROOT}/", '')} references #{id}, " \
                        "which is not in config/aws/controls.yml"
      end
    end
  end
end
