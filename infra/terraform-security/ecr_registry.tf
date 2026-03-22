resource "aws_ecr_registry_scanning_configuration" "main" {
  count = var.enable_ecr_registry_scan ? 1 : 0

  scan_type = "ENHANCED"

  rule {
    scan_frequency = "CONTINUOUS_SCAN"

    repository_filter {
      filter      = "*"
      filter_type = "WILDCARD"
    }
  }
}
