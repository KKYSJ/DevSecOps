resource "aws_cloudwatch_log_group" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0

  name              = local.cloudtrail_log_group_name
  retention_in_days = var.cloudtrail_log_retention_in_days

  tags = merge(local.common_tags, { Name = local.cloudtrail_log_group_name })
}

data "aws_iam_policy_document" "cloudtrail_assume_role" {
  count = var.enable_cloudtrail ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0

  name               = "${local.name_prefix}-cloudtrail-role"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume_role[0].json

  tags = local.common_tags
}

data "aws_iam_policy_document" "cloudtrail_logs" {
  count = var.enable_cloudtrail ? 1 : 0

  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    resources = ["${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  count = var.enable_cloudtrail ? 1 : 0

  name   = "${local.name_prefix}-cloudtrail-logs"
  role   = aws_iam_role.cloudtrail[0].id
  policy = data.aws_iam_policy_document.cloudtrail_logs[0].json
}

resource "aws_cloudtrail" "main" {
  count = var.enable_cloudtrail ? 1 : 0

  name                          = local.trail_name
  s3_bucket_name                = local.security_logs_bucket_name
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail[0].arn

  tags = merge(local.common_tags, { Name = local.trail_name })

  depends_on = [
    aws_s3_bucket_policy.security_logs,
    aws_iam_role_policy.cloudtrail_logs
  ]
}
