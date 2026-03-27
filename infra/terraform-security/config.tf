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

    recording_strategy {
      use_only = "ALL_SUPPORTED_RESOURCE_TYPES"
    }
  }

  recording_mode {
    recording_frequency = var.config_recording_frequency

    dynamic "recording_mode_override" {
      for_each = length(var.config_recording_override_resource_types) > 0 ? [1] : []

      content {
        recording_frequency = var.config_recording_override_frequency
        resource_types      = var.config_recording_override_resource_types
      }
    }
  }
}

resource "aws_config_delivery_channel" "main" {
  count = var.enable_config ? 1 : 0

  name           = var.config_delivery_channel_name
  s3_bucket_name = local.security_logs_bucket_name
  s3_key_prefix  = var.config_s3_key_prefix

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
