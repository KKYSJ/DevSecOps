data "aws_iam_policy_document" "config_assume_role" {
  count = var.enable_config && var.create_config_service_role ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config" {
  count = var.enable_config && var.create_config_service_role ? 1 : 0

  name               = "${local.name_prefix}-config-role"
  assume_role_policy = data.aws_iam_policy_document.config_assume_role[0].json

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  count = var.enable_config && var.create_config_service_role ? 1 : 0

  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  count = var.enable_config ? 1 : 0

  name     = var.config_recorder_name
  role_arn = local.config_recorder_role_arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  count = var.enable_config ? 1 : 0

  name           = var.config_delivery_channel_name
  s3_bucket_name = local.security_logs_bucket_name
  s3_key_prefix  = "config"

  depends_on = [
    aws_s3_bucket_policy.security_logs
  ]
}

resource "aws_config_configuration_recorder_status" "main" {
  count = var.enable_config ? 1 : 0

  name       = aws_config_configuration_recorder.main[0].name
  is_enabled = true

  depends_on = [
    aws_config_delivery_channel.main
  ]
}

resource "aws_config_config_rule" "managed" {
  for_each = var.enable_config && var.enable_config_rules ? local.enabled_config_rules : {}

  name = each.key

  source {
    owner             = "AWS"
    source_identifier = each.value
  }

  depends_on = [
    aws_config_configuration_recorder_status.main
  ]
}
