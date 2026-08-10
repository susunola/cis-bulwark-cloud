# frozen_string_literal: true

module Cis
  # Turns filter expressions into a concrete set of controls.
  #
  # Filters are read from the environment so that bin/cis and the terraform
  # stacks resolve to the same selection. bin/cis translates its flags into
  # these variables before exec'ing terraform.
  #
  #   CIS_ONLY      comma separated id globs, e.g. "3.5,4.*"   (authoritative)
  #   CIS_EXCLUDE   comma separated id globs, applied last
  #   CIS_SECTIONS  comma separated section numbers, e.g. "3,4"
  #   CIS_TAGS      comma separated tags, matches if the control has ANY of them
  #   CIS_PROFILE   level1 | level2
  #
  # Precedence: CIS_ONLY replaces the `enabled:` baseline entirely; the other
  # filters narrow whatever baseline is in play; CIS_EXCLUDE always wins.
  class Selector
    attr_reader :catalog, :only, :exclude, :sections, :tags, :profile

    def self.from_env(catalog, env = ENV)
      new(
        catalog,
        only:     split(env["CIS_ONLY"]),
        exclude:  split(env["CIS_EXCLUDE"]),
        sections: split(env["CIS_SECTIONS"]),
        tags:     split(env["CIS_TAGS"]),
        profile:  env["CIS_PROFILE"]
      )
    end

    def self.split(value)
      value.to_s.split(",").map(&:strip).reject(&:empty?)
    end

    def initialize(catalog, only: [], exclude: [], sections: [], tags: [], profile: nil)
      @catalog  = catalog
      @only     = Array(only)
      @exclude  = Array(exclude)
      @sections = Array(sections).map(&:to_s)
      @tags     = Array(tags)
      @profile  = normalize_profile(profile)
      validate!
    end

    # Every control that survives the filters, regardless of whether Terraform
    # can do anything about it. Manual controls stay in so `scan` can report
    # them instead of silently dropping coverage.
    def selected
      @selected ||= begin
        base = only.empty? ? catalog.controls.select(&:enabled) : match_globs(catalog.controls, only)
        base = base.select { |c| sections.include?(c.section) } unless sections.empty?
        base = base.select { |c| (c.tags & tags).any? }         unless tags.empty?
        base = base.select { |c| c.level <= profile }           if profile
        base = base.reject { |c| glob_any?(c.id, exclude) }     unless exclude.empty?
        base.sort_by(&:sort_key)
      end
    end

    def remediable
      selected.select(&:remediable?)
    end

    def detectable
      selected.select(&:detectable?)
    end

    # Selected but Terraform cannot enforce it - still worth listing so the
    # operator knows the gap exists.
    def not_remediable
      selected.reject(&:remediable?)
    end

    # Selected but Terraform cannot assess it.
    def not_detectable
      selected.reject(&:detectable?)
    end

    def ids
      selected.map(&:id)
    end

    def empty?
      selected.empty?
    end

    def stacks_for_apply
      Cis::HARDENING_STACKS & remediable.map(&:stack).compact.uniq
    end

    def summary
      {
        "selected"    => selected.size,
        "of"          => catalog.size,
        "remediable"  => remediable.size,
        "detectable"  => detectable.size,
        "manual"      => selected.count(&:manual?),
        "stacks"      => stacks_for_apply
      }
    end

    # Reproduce this selection in a child process.
    def to_env
      {
        "CIS_ONLY"     => only.join(","),
        "CIS_EXCLUDE"  => exclude.join(","),
        "CIS_SECTIONS" => sections.join(","),
        "CIS_TAGS"     => tags.join(","),
        "CIS_PROFILE"  => profile ? "level#{profile}" : ""
      }
    end

    private

    def match_globs(controls, patterns)
      controls.select { |c| glob_any?(c.id, patterns) }
    end

    def glob_any?(id, patterns)
      patterns.any? { |p| p == id || File.fnmatch?(p, id) }
    end

    def normalize_profile(value)
      return nil if value.nil? || value.to_s.strip.empty?
      case value.to_s.strip.downcase
      when "1", "l1", "level1", "level 1", "level-1" then 1
      when "2", "l2", "level2", "level 2", "level-2" then 2
      else
        raise Error, "unknown profile #{value.inspect}; expected level1 or level2"
      end
    end

    # Fail loudly on a filter that matches nothing - a silent empty run is the
    # worst possible outcome for a compliance tool.
    def validate!
      known = catalog.ids
      (only + exclude).each do |pattern|
        next if known.any? { |id| id == pattern || File.fnmatch?(pattern, id) }
        raise Error, "filter #{pattern.inspect} matches no control in the benchmark"
      end
      sections.each do |sid|
        next if known.any? { |id| id.split(".").first == sid }
        raise Error, "unknown section #{sid.inspect}"
      end
      tags.each do |tag|
        next if catalog.controls.any? { |c| c.tags.include?(tag) }
        raise Error, "unknown tag #{tag.inspect}"
      end
    end
  end
end
