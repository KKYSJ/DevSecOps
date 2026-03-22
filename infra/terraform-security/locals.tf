locals {
  name_prefix = "${var.project_name}-${var.environment}"

  common_tags = merge(
    var.default_tags,
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Stack       = "security-baseline"
    }
  )

  trail_name                = coalesce(var.trail_name, "${local.name_prefix}-trail")
  cloudtrail_log_group_name = coalesce(var.cloudtrail_log_group_name, "/aws/cloudtrail/${local.name_prefix}")
  security_logs_bucket_name = try(aws_s3_bucket.security_logs[0].bucket, var.security_logs_bucket_name)
  cloudtrail_bucket_name    = try(aws_s3_bucket.cloudtrail[0].bucket, var.cloudtrail_bucket_name, try(aws_s3_bucket.security_logs[0].bucket, null))
  config_recorder_role_arn  = var.enable_config && var.create_config_service_role ? aws_iam_role.config[0].arn : var.config_recorder_role_arn
  flow_logs_log_group_name  = coalesce(var.flow_logs_log_group_name, "/aws/vpc/flowlogs/${local.name_prefix}")
  flow_logs_log_group_arn   = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:${local.flow_logs_log_group_name}"
  flow_logs_role_arn        = var.enable_flow_logs && var.create_flow_logs_iam_role ? aws_iam_role.flow_logs[0].arn : var.flow_logs_role_arn
  effective_flow_log_tags   = length(var.flow_log_tags) > 0 ? var.flow_log_tags : local.common_tags

  config_rule_identifiers = {
    cloudtrail-enabled                   = "CLOUD_TRAIL_ENABLED"
    cloud-trail-cloud-watch-logs-enabled = "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED"
    vpc-default-security-group-closed    = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
    rds-instance-public-access-check     = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
    db-instance-backup-enabled           = "RDS_INSTANCE_BACKUP_ENABLED"
    cmk-backing-key-rotation-enabled     = "CMK_BACKING_KEY_ROTATION_ENABLED"
  }

  enabled_config_rules = {
    for name in var.config_rule_names :
    name => local.config_rule_identifiers[name]
    if contains(keys(local.config_rule_identifiers), name)
  }
}
