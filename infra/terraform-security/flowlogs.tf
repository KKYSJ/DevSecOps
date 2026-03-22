resource "aws_cloudwatch_log_group" "flow_logs" {
  count = var.enable_flow_logs && var.create_flow_logs_log_group ? 1 : 0

  name              = local.flow_logs_log_group_name
  retention_in_days = var.flow_logs_log_retention_in_days

  tags = merge(local.common_tags, { Name = local.flow_logs_log_group_name })
}

data "aws_iam_policy_document" "flow_logs_assume_role" {
  count = var.enable_flow_logs && var.create_flow_logs_iam_role ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  count = var.enable_flow_logs && var.create_flow_logs_iam_role ? 1 : 0

  name               = "${local.name_prefix}-flow-logs-role"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume_role[0].json

  tags = local.common_tags
}

data "aws_iam_policy_document" "flow_logs" {
  count = var.enable_flow_logs && var.create_flow_logs_iam_role ? 1 : 0

  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams"
    ]

    resources = [
      local.flow_logs_log_group_arn,
      "${local.flow_logs_log_group_arn}:*"
    ]
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  count = var.enable_flow_logs && var.create_flow_logs_iam_role ? 1 : 0

  name   = "${local.name_prefix}-flow-logs"
  role   = aws_iam_role.flow_logs[0].id
  policy = data.aws_iam_policy_document.flow_logs[0].json
}

resource "aws_flow_log" "vpc" {
  for_each = var.enable_flow_logs ? toset(var.managed_vpc_ids) : toset([])

  iam_role_arn         = local.flow_logs_role_arn
  log_destination      = local.flow_logs_log_group_arn
  log_destination_type = "cloud-watch-logs"
  traffic_type         = var.flow_log_traffic_type
  vpc_id               = each.value

  tags = local.effective_flow_log_tags

  depends_on = [
    aws_cloudwatch_log_group.flow_logs,
    aws_iam_role_policy.flow_logs
  ]
}
