resource "aws_cloudwatch_log_group" "services" {
  for_each = toset(var.service_names)

  name              = "/aws/ecs/${var.project_name}/${var.environment}/${each.value}"
  retention_in_days = var.log_retention_in_days

  tags = merge(var.tags, { Name = each.value })
}

resource "aws_sns_topic" "alerts" {
  count = var.create_alerts_topic ? 1 : 0

  name = "${var.project_name}-${var.environment}-alerts"

  tags = merge(var.tags, { Name = "${var.project_name}-${var.environment}-alerts" })
}
