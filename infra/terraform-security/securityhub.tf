resource "aws_securityhub_account" "main" {
  count = var.enable_securityhub ? 1 : 0

  auto_enable_controls      = true
  control_finding_generator = "SECURITY_CONTROL"
  enable_default_standards  = false
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  count = var.enable_securityhub ? 1 : 0

  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [
    aws_securityhub_account.main
  ]
}
