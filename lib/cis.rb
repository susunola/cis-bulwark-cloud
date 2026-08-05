# frozen_string_literal: true

# CIS Tencent Cloud Foundation Benchmark v1.0.0.
#
# This file is required from config/app.rb, which means everything here is
# available both to Terraspace configuration (config.all.include_stacks) and to
# the ERB binding used when rendering app/stacks/*/tfvars/*.tfvars. That is what
# keeps stack-level filtering and control-level filtering in lockstep.

require "yaml"
require "json"

require_relative "cis/control"
require_relative "cis/catalog"
require_relative "cis/selector"
require_relative "cis/reporter"
require_relative "cis/runner"

module Cis
  ROOT = File.expand_path("..", __dir__)

  # Terraspace stacks that perform read-only assessment.
  AUDIT_STACK = "audit"

  # Terraspace stacks that write. Order is stable so runs are reproducible.
  HARDENING_STACKS = %w[iam logging network storage database kubernetes].freeze

  class Error < StandardError; end

  class << self
    def catalog
      @catalog ||= Catalog.load(File.join(ROOT, "config", "controls.yml"))
    end

    # Selection is derived from the environment so that every process in the
    # run (bin/cis, terraspace, the tfvars ERB) resolves to the same answer.
    def selector
      @selector ||= Selector.from_env(catalog)
    end

    # Explicitly rebuild - used by bin/cis after it translates CLI flags into
    # environment variables, and by the test suite.
    def reset!
      @selector = nil
      @catalog = nil
      self
    end

    # Control ids handed to a stack's `enabled_controls` variable.
    #
    # For hardening stacks this is the set of selected controls that both
    # belong to the stack and are actually remediable by Terraform.
    def controls_for_stack(stack)
      selector.remediable.select { |c| c.stack == stack }.map(&:id)
    end

    # Control ids the audit stack should evaluate.
    def controls_for_audit
      selector.detectable.map(&:id)
    end

    # Stacks Terraspace is allowed to touch for the current action.
    # TS_CIS_ACTION is set by bin/cis; default to a safe read-only posture.
    def active_stacks
      case ENV["TS_CIS_ACTION"]
      when "apply"
        stacks = selector.remediable.map(&:stack).compact.uniq
        HARDENING_STACKS & stacks
      when "scan"
        selector.detectable.empty? ? [] : [AUDIT_STACK]
      else
        # No action declared (e.g. a bare `terraspace list`): allow everything
        # so the project stays introspectable.
        [AUDIT_STACK] + HARDENING_STACKS
      end
    end
  end
end
