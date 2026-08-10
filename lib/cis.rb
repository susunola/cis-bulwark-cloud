# frozen_string_literal: true

# CIS cloud foundation benchmarks — plain Terraform implementation.
#
# The Ruby layer (catalog, selector, reporter) reads the per-cloud control
# registry; the runner shells out to `terraform` directly against the
# self-contained stacks. The active cloud is selected with CIS_CLOUD
# (default: tencent); `bin/cis --cloud aws ...` sets it for one run.

require "yaml"
require "json"

require_relative "cis/control"
require_relative "cis/catalog"
require_relative "cis/selector"
require_relative "cis/reporter"
require_relative "cis/runner"

module Cis
  ROOT = File.expand_path("..", __dir__)

  # Clouds with a full scan/apply implementation (registry + stacks).
  IMPLEMENTED_CLOUDS = %w[tencent aws azure].freeze
  # Clouds whose benchmark is published under benchmarks/ but not yet mapped
  # onto a Terraform provider; `cis` refuses to run against them.
  REFERENCE_CLOUDS = %w[alibaba gcp].freeze

  AUDIT_STACK = "audit"

  # Stacks that write, per cloud. Order is stable so runs are reproducible.
  # tencent keeps its legacy layout (stacks/<name>); later clouds live under
  # stacks/<cloud>/<name>.
  HARDENING_STACKS = {
    "tencent" => %w[iam logging network storage database kubernetes].freeze,
    # network has no remediable control in AWS v7.0.0 (6.3/6.4/6.5/6.7 are
    # detect-only), so it is not a hardening stack.
    "aws"     => %w[iam logging storage database].freeze,
    # azure: remediable controls live in network (7.6 watcher), security
    # (8.1.13 contact) and storage (9.x).
    "azure"   => %w[network security storage].freeze,
  }.freeze

  class Error < StandardError; end

  class << self
    # Active cloud, from CIS_CLOUD. Raises for reference-only clouds.
    def cloud
      name = ENV["CIS_CLOUD"] || "tencent"
      return name if IMPLEMENTED_CLOUDS.include?(name)
      raise Error, "#{name.inspect} is a reference-only benchmark (catalog published, " \
                   "no Terraform mapping yet); supported: #{IMPLEMENTED_CLOUDS.join(', ')}" \
        if REFERENCE_CLOUDS.include?(name)
      raise Error, "unknown cloud #{name.inspect}; expected one of " \
                   "#{(IMPLEMENTED_CLOUDS + REFERENCE_CLOUDS).join(', ')}"
    end

    def hardening_stacks
      HARDENING_STACKS.fetch(cloud)
    end

    def catalog
      @catalog ||= Catalog.load(catalog_path)
    end

    def catalog_path
      cloud == "tencent" ? File.join(ROOT, "config", "controls.yml")
                         : File.join(ROOT, "config", cloud, "controls.yml")
    end

    # Selection is derived from the environment.
    def selector
      @selector ||= Selector.from_env(catalog)
    end

    def reset!
      @selector = nil
      @catalog = nil
      self
    end

    def controls_for_stack(stack)
      selector.remediable.select { |c| c.stack == stack }.map(&:id)
    end

    def controls_for_audit
      selector.detectable.map(&:id)
    end

    # Directory for a stack's .tf files.
    def stack_dir(stack)
      base = cloud == "tencent" ? "stacks" : File.join("stacks", cloud)
      File.join(ROOT, base, stack)
    end
  end
end
