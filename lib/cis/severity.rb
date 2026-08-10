# frozen_string_literal: true

module Cis
  # Risk severity for findings, inferred from a control's tags.
  #
  # CIS benchmarks do not grade severity; Prowler and friends add their own
  # classification. Ours is a conservative mapping over the existing tag
  # vocabulary so it costs nothing to maintain and never contradicts the
  # registry:
  #
  #   critical - account-takeover / data-exposure territory: root usage,
  #              missing MFA, public access, admin ports, exposed keys
  #   high     - enforceable hardening with real impact: password policy,
  #              encryption, TLS, ingress control, storage/keyvault
  #   medium   - logging / audit / monitoring gaps
  #   low      - governance and review items
  module Severity
    LEVELS = %w[critical high medium low].freeze

    RULES = [
      ["critical", %w[root mfa admin access-key public public-access public-ip admin-ports cloudshell bastion] ],
      ["high",     %w[password-policy encryption ssl tls ingress security-group network keyvault databricks rds sql disk nacl] ],
      ["medium",   %w[logging audit monitoring retention sink trail flow-log actiontrail defender kms alert] ],
    ].freeze

    module_function

    def of(tags)
      RULES.each do |level, keys|
        return level unless (Array(tags) & keys).empty?
      end
      "low"
    end
  end
end
