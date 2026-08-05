# frozen_string_literal: true

# CIS Tencent Cloud Foundation Benchmark v1.0.0 — plain Terraform version.
#
# The Ruby layer (catalog, selector, reporter) is identical to the Terraspace
# version. Only the runner differs: it shells out to `terraform` directly
# instead of going through `terraspace`.

require "yaml"
require "json"

require_relative "cis/control"
require_relative "cis/catalog"
require_relative "cis/selector"
require_relative "cis/reporter"
require_relative "cis/runner"

module Cis
  ROOT = File.expand_path("..", __dir__)

  AUDIT_STACK = "audit"

  # Stacks that write. Order is stable so runs are reproducible.
  HARDENING_STACKS = %w[iam logging network storage database kubernetes].freeze

  class Error < StandardError; end

  class << self
    def catalog
      @catalog ||= Catalog.load(File.join(ROOT, "config", "controls.yml"))
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
      File.join(ROOT, "stacks", stack)
    end
  end
end
