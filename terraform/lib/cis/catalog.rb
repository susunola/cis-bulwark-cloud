# frozen_string_literal: true

module Cis
  # The parsed config/controls.yml, i.e. every recommendation in the benchmark.
  class Catalog
    attr_reader :benchmark, :version, :released, :sections, :controls

    def self.load(path)
      unless File.exist?(path)
        raise Error, "control registry not found: #{path}"
      end
      raw = YAML.safe_load(File.read(path), permitted_classes: [], aliases: false)
      new(raw)
    end

    def initialize(raw)
      @benchmark = raw["benchmark"]
      @version   = raw["version"]
      @released  = raw["released"]
      @sections  = raw["sections"] || {}
      @controls  = Array(raw["controls"]).map { |h| Control.new(h) }
                                         .sort_by(&:sort_key)
      assert_unique_ids!
    end

    def [](id)
      index[id.to_s]
    end

    def ids
      controls.map(&:id)
    end

    def section_title(sid)
      sections[sid.to_s] || "Section #{sid}"
    end

    def size
      controls.size
    end

    private

    def index
      @index ||= controls.each_with_object({}) { |c, h| h[c.id] = c }
    end

    def assert_unique_ids!
      dupes = ids.tally.select { |_, n| n > 1 }.keys
      raise Error, "duplicate control ids in registry: #{dupes.join(', ')}" if dupes.any?
    end
  end
end
