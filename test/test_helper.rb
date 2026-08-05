# frozen_string_literal: true

# Test harness for the CIS Tencent Cloud toolkit.
#
#   ruby test/run.rb                # everything
#   ruby test/selector_test.rb      # one file
#
# Nothing here talks to a cloud API, and nothing here needs credentials.
#
# The Terraform assertions are *structural*: they read the HCL as text and hold
# it against config/controls.yml. That is the only way to catch the class of
# bug that matters most in a compliance tool - "the registry routes 4.7 to the
# storage stack, but storage/main.tf never implements it" - before an operator
# discovers it from a clean-looking report.

require "minitest/autorun"
require "json"
require "open3"
require "set"

require_relative "../lib/cis"

module CisTest
  ROOT = Cis::ROOT
  BIN  = File.join(ROOT, "bin", "cis")

  # Everything that can influence a selection. Tests clear all of it so a
  # developer with CIS_PROFILE exported in their shell still sees green.
  FILTER_ENV = %w[
    CIS_ONLY CIS_EXCLUDE CIS_SECTIONS CIS_TAGS CIS_PROFILE TS_CIS_ACTION
  ].freeze

  module_function

  def stack_path(stack, *parts)
    File.join(ROOT, "app", "stacks", stack, *parts)
  end

  def module_path(mod, *parts)
    File.join(ROOT, "app", "modules", mod, *parts)
  end

  # Swap in an explicit CIS_* environment for the duration of the block.
  # Keys not mentioned are removed, not inherited.
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

  # Run bin/cis in a clean environment and capture everything.
  def run_cli(*args, env: {})
    child = FILTER_ENV.each_with_object({}) { |k, h| h[k] = nil }
    child.merge!(env.transform_keys(&:to_s))
    # Terraspace is never reached in these tests (they all pass --dry-run),
    # but be explicit about it so a stray invocation fails loudly.
    child["TS_QUIET"] = "1"
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

  # ---- a very small, very deliberate HCL reader ---------------------------
  #
  # Not a parser. It masks strings and comments so that brace counting is
  # trustworthy, then answers three questions:
  #
  #   string_list  what is in `name = [ "a", "b" ]`
  #   object_keys  what are the direct keys of `name = { "1.2" = {...} }`
  #   top_blocks   every top-level block, with its body
  #
  # Everything it reads has been through `terraform fmt` (asserted by
  # wiring_test.rb), so top-level blocks reliably start in column 0.
  module Hcl
    BLOCK_HEAD = /^([a-z_]+)((?:[ \t]+"[^"]*")*)[ \t]*\{/.freeze

    module_function

    def read(path)
      File.read(path)
    end

    # Replace the contents of strings and comments with spaces, preserving
    # length so offsets stay comparable with the original text.
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

    # depth[i] = nesting depth of braces/brackets *before* character i.
    def depth_map(masked)
      depth = 0
      masked.each_char.map do |ch|
        here = depth
        depth += 1 if ch == "{" || ch == "["
        depth -= 1 if ch == "}" || ch == "]"
        here
      end
    end

    # Offset of the closing delimiter that matches the opener at `open`.
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

    # Every quoted string inside `name = [ ... ]`, in source order.
    def string_list(src, name)
      masked = mask(src)
      m = masked.match(/\b#{Regexp.escape(name)}\s*=\s*\[/)
      return nil unless m

      open  = masked.index("[", m.begin(0))
      close = match_delimiter(masked, open)
      src[(open + 1)...close].scan(/"([^"]*)"/).flatten
    end

    # Direct (depth-1) keys of `name = { ... }`, in source order.
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

    # [{ type:, labels:, body:, header: }] for every top-level block.
    def top_blocks(src)
      masked = mask(src)
      depths = depth_map(masked)
      blocks = []
      masked.scan(BLOCK_HEAD) do
        m = Regexp.last_match
        next unless depths[m.begin(0)].zero?

        open   = masked.index("{", m.begin(0))
        close  = match_delimiter(masked, open)
        # Labels have to come from the original: the masked copy blanked them.
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

    # name => defining expression, for every `locals { }` block in the file.
    #
    # An assignment runs until the next depth-1 assignment or the end of the
    # block, which is exact for HCL: attributes at one level are sequential.
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

# Base class so every test gets a pristine selection and a clean registry.
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
