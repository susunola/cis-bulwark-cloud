# frozen_string_literal: true

module Cis
  # A single CIS recommendation plus how it maps onto the Terraform provider.
  class Control
    ATTRS = %i[id title assessment profile enabled remediate detect stack tags].freeze
    attr_reader(*ATTRS)

    def initialize(hash)
      @id         = hash.fetch("id").to_s
      @title      = hash.fetch("title").to_s
      @assessment = hash.fetch("assessment", "Manual").to_s
      @profile    = hash.fetch("profile", "Level 1").to_s
      @enabled    = hash.fetch("enabled", true) ? true : false
      @remediate  = hash.fetch("remediate", "none").to_s
      @detect     = hash.fetch("detect", "none").to_s
      @stack      = hash["stack"].nil? || hash["stack"] == "null" ? nil : hash["stack"].to_s
      @tags       = Array(hash["tags"]).map(&:to_s)
      validate!
    end

    def section
      id.split(".").first
    end

    # Sortable key: "3.10" must come after "3.9".
    def sort_key
      id.split(".").map(&:to_i)
    end

    def remediable?
      remediate == "terraform"
    end

    def detectable?
      detect == "terraform"
    end

    # Neither enforceable nor assessable by Terraform - the operator has to do
    # it in the console and record the result out of band.
    def manual?
      !remediable? && !detectable?
    end

    def level
      profile[/\d+/].to_i
    end

    def to_h
      {
        "id" => id, "title" => title, "assessment" => assessment,
        "profile" => profile, "enabled" => enabled, "remediate" => remediate,
        "detect" => detect, "stack" => stack, "tags" => tags
      }
    end

    private

    def validate!
      unless id =~ /\A\d+\.\d+\z/
        raise Error, "control id must look like '<section>.<n>', got #{id.inspect}"
      end
      unless %w[terraform none].include?(remediate)
        raise Error, "#{id}: remediate must be terraform|none, got #{remediate.inspect}"
      end
      unless %w[terraform none].include?(detect)
        raise Error, "#{id}: detect must be terraform|none, got #{detect.inspect}"
      end
      if remediable? && stack.nil?
        raise Error, "#{id}: remediate=terraform requires a stack"
      end
      if detectable? && stack.nil?
        raise Error, "#{id}: detect=terraform requires a stack"
      end
      if stack && !manual_stack_ok?
        raise Error, "#{id}: unknown stack #{stack.inspect}"
      end
    end

    def manual_stack_ok?
      Cis::HARDENING_STACKS.include?(stack)
    end
  end
end
