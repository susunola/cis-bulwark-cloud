# State lives under <project>/state, NOT inside .terraspace-cache, so that
# `terraspace clean cache` cannot destroy the record of what has been applied.
#
# For anything beyond a single operator, switch this to a COS backend:
#
#   terraform {
#     backend "cos" {
#       region = "ap-guangzhou"
#       bucket = "tfstate-1250000000"
#       prefix = "cis/<%= expansion(':ENV') %>/<%= expansion(':MOD_NAME') %>"
#     }
#   }
#
terraform {
  backend "local" {
    path = "<%= Cis::ROOT %>/state/<%= expansion(':ENV') %>/<%= expansion(':MOD_NAME') %>.tfstate"
  }
}
