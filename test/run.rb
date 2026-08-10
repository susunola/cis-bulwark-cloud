# frozen_string_literal: true

# Runs every spec in one process.
#
#   ruby test/run.rb
#
# Load order is deliberate: catalog first, because if config/controls.yml is
# wrong then every other failure downstream is noise.

require_relative "test_helper"

%w[
  catalog_test
  selector_test
  wiring_test
  cli_test
  runner_test
  benchmarks_test
  aws_wiring_test
  azure_wiring_test
  gcp_wiring_test
  alibaba_wiring_test
].each { |name| require_relative name }
