# frozen_string_literal: true

# Test harness for the CIS Tencent Cloud Foundation Benchmark — plain Terraform.
#
#   ruby test/run.rb                # everything
#   ruby test/selector_test.rb      # one file
#
# Nothing here talks to a cloud API, and nothing here needs credentials.

require "minitest/autorun"
require "json"
require "open3"
require "set"

require_relative "../lib/cis"

module CisTest
  ROOT = Cis::ROOT
  BIN  = File.join(ROOT, "bin", "cis")

  FILTER_ENV = %w[
    CIS_ONLY CIS_EXCLUDE CIS_SECTIONS CIS_TAGS CIS_PROFILE
  ].freeze

  module_function

  def stack_path(stack, *parts)
    File.join(ROOT, "stacks", stack, *parts)
  end

  def module_path(mod, *parts)
    File.join(ROOT, "modules", mod, *parts)
  end

  def with_env(vars = {})
    saved = FILTER_ENV.each_with_object({}) { |k, h| h[k] = ENV[k] }
    FILTER_ENV.each { |k| ENV.delete(k) }
    vars.each { |k, v| ENV[k.to_s] = v&.to_s }
    Cis.reset!
    yield
  ensure
    saved.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    Cis.reset!
  end

  def run_cli(*args, env: {})
    child = FILTER_ENV.each_with_object({}) { |k, h| h[k] = nil }
    child.merge!(env.transform_keys(&:to_s))
    out, err, status = Open3.capture3(child, RbConfig.ruby, BIN, *args, chdir: ROOT)
    Result.new(out, err, status.exitstatus)
  end

  Result = Struct.new(:stdout, :stderr, :status) do
    def json
      JSON.parse(stdout)
    end

    def to_s
      "exit=#{status}\n--- stdout ---\n#{stdout}\n--- stderr ---\n#{stderr}"
    end
  end

  module Hcl
    BLOCK_HEAD = /^([a-z_]+)((?:[ \t]+"[^"]*")*)[ \t]*\{/.freeze

    module_function

    def read(path)
      File.read(path)
    end

    def mask(src)
      out = src.dup
      i = 0
      n = src.length
      while i < n
        case src[i]
        when '"'
          j = i + 1
          j += 1 while j < n && !(src[j] == '"' && src[j - 1] != "\\")
          j = [j, n - 1].min
          out[(i + 1)...j] = " " * (j - i - 1) if j > i + 1
          i = j + 1
        when "#"
          j = src.index("\n", i) || n
          out[i...j] = " " * (j - i)
          i = j
        when "/"
          if src[i + 1] == "/"
            j = src.index("\n", i) || n
            out[i...j] = " " * (j - i)
            i = j
          elsif src[i + 1] == "*"
            j = (src.index("*/", i) || n - 2) + 2
            out[i...j] = src[i...j].gsub(/[^\n]/, " ")
            i = j
          else
            i += 1
          end
        else
          i += 1
        end
      end
      out
    end

    def depth_map(masked)
      depth = 0
      masked.each_char.map do |ch|
        here = depth
        depth += 1 if ch == "{" || ch == "["
        depth -= 1 if ch == "}" || ch == "]"
        here
      end
    end

    def match_delimiter(masked, open)
      pairs  = { "{" => "}", "[" => "]" }
      closer = pairs.fetch(masked[open])
      depth  = 0
      i      = open
      while i < masked.length
        depth += 1 if masked[i] == masked[open]
        depth -= 1 if masked[i] == closer
        return i if depth.zero?
        i += 1
      end
      raise "unbalanced #{masked[open]} at offset #{open}"
    end

    def string_list(src, name)
      masked = mask(src)
      m = masked.match(/\b#{Regexp.escape(name)}\s*=\s*\[/)
      return nil unless m

      open  = masked.index("[", m.begin(0))
      close = match_delimiter(masked, open)
      src[(open + 1)...close].scan(/"([^"]*)"/).flatten
    end

    def object_keys(src, name)
      masked = mask(src)
      m = masked.match(/\b#{Regexp.escape(name)}\s*=\s*\{/)
      return nil unless m

      open   = masked.index("{", m.begin(0))
      close  = match_delimiter(masked, open)
      depths = depth_map(masked)
      base   = depths[open] + 1

      keys = []
      src.scan(/"([^"]*)"\s*=/) do
        at = Regexp.last_match.begin(0)
        next unless at > open && at < close
        next unless depths[at] == base
        keys << Regexp.last_match(1)
      end
      keys
    end

    def top_blocks(src)
      masked = mask(src)
      depths = depth_map(masked)
      blocks = []
      masked.scan(BLOCK_HEAD) do
        m = Regexp.last_match
        next unless depths[m.begin(0)].zero?

        open   = masked.index("{", m.begin(0))
        close  = match_delimiter(masked, open)
        header = src[m.begin(0)...open]
        blocks << {
          type:       m[1],
          labels:     header.scan(/"([^"]*)"/).flatten,
          header:     header.strip,
          body:       src[(open + 1)...close],
          body_begin: open + 1,
          body_end:   close
        }
      end
      blocks
    end

    def locals_map(src)
      masked = mask(src)
      depths = depth_map(masked)
      out    = {}

      top_blocks(src).select { |b| b[:type] == "locals" }.each do |block|
        start = block[:body_begin]
        stop  = block[:body_end]
        base  = depths[start]

        starts = []
        src.scan(/^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=/) do
          at = Regexp.last_match.begin(1)
          next unless at >= start && at < stop
          next unless depths[at] == base
          starts << [at, Regexp.last_match(1), Regexp.last_match.end(0)]
        end

        starts.each_with_index do |(_, name, expr_begin), idx|
          expr_end = starts[idx + 1] ? starts[idx + 1][0] : stop
          out[name] = src[expr_begin...expr_end]
        end
      end
      out
    end
  end
end

class CisTestCase < Minitest::Test
  include CisTest

  def setup
    @saved = CisTest::FILTER_ENV.each_with_object({}) { |k, h| h[k] = ENV[k] }
    CisTest::FILTER_ENV.each { |k| ENV.delete(k) }
    Cis.reset!
  end

  def teardown
    @saved.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    Cis.reset!
  end

  def catalog
    Cis.catalog
  end

  def select(**kwargs)
    Cis::Selector.new(catalog, **kwargs)
  end

  def hardening_stacks
    Cis::HARDENING_STACKS
  end
end
