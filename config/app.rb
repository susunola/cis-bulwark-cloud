# frozen_string_literal: true

# Loading the toolkit here does two jobs at once:
#   1. it lets this file compute config.all.include_stacks, and
#   2. it puts the Cis constant into the binding Terraspace uses to render the
#      ERB inside app/stacks/*/tfvars/*.tfvars, which is how control-level
#      filtering reaches Terraform.
require_relative "../lib/cis"

Terraspace.configure do |config|
  config.logger.level = ENV.fetch("TS_LOG", "info")

  # The default cache path embeds :REGION, which is resolved by a cloud plugin.
  # There is no Terraspace plugin for Tencent Cloud, so drop that segment and
  # keep the layout predictable: .terraspace-cache/<env>/stacks/<stack>
  config.build.cache_dir = ".terraspace-cache/:ENV/:BUILD_DIR"

  # Stack-level filtering. `cis` sets TS_CIS_ACTION and the CIS_* filter
  # variables before shelling out, so a hand-run `terraspace all plan` honours
  # exactly the same selection the CLI would.
  config.all.include_stacks = Cis.active_stacks
end
