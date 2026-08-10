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
      # 1.1 (tencent) and 1.1.1 (AWS/Alibaba/GCP/Azure) ids are both valid.
      unless id =~ /\A\d+(\.\d+){1,2}\z/
        raise Error, "control id must look like '<section>.<n>' or '<section>.<group>.<n>', got #{id.inspect}"
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
      if stack && !(stack =~ /\A[a-z][a-z0-9_-]*\z/)
        raise Error, "#{id}: malformed stack name #{stack.inspect}"
      end
    end

    # Stack attribution is validated structurally here; whether a stack really
    # exists on disk is enforced by the wiring tests, which cross-check every
    # registry stack against the stacks a cloud ships.
    def known_stack?
      stack =~ /\A[a-z][a-z0-9_-]*\z/
    end
  end
end
