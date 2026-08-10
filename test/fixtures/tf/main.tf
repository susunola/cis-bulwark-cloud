resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length    = 14
  password_reuse_prevention  = 24
}

resource "aws_ebs_encryption_by_default" "d" {
  enabled = true
}

resource "aws_cloudtrail" "trail" {
  name = "ct"
  s3_bucket_name = "b"
}

resource "aws_db_instance" "db" {
  identifier = "x"
  engine = "mysql"
  publicly_accessible = false
}

resource "aws_instance" "web" {
  ami = "ami-1"
  metadata_options {
    http_tokens = "required"
  }
}

resource "azurerm_storage_account" "logs" {
  name = "logs"
  resource_group_name = "rg"
  https_traffic_only_enabled = true
  min_tls_version = "TLS1_2"
  account_tier = "Standard"
  account_replication_type = "LRS"
}
