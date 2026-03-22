variable "project_name" {
  description = "Project prefix used across security resources."
  type        = string
  default     = "secureflow"
}

variable "environment" {
  description = "Deployment environment name such as dev or prod."
  type        = string
}

variable "aws_region" {
  description = "AWS region to manage security resources in."
  type        = string
}

variable "default_tags" {
  description = "Additional tags applied to all resources."
  type        = map(string)
  default     = {}
}

variable "trail_name" {
  description = "Optional explicit CloudTrail name."
  type        = string
  default     = null
  nullable    = true
}

variable "cloudtrail_log_group_name" {
  description = "Optional explicit CloudWatch log group name for CloudTrail delivery."
  type        = string
  default     = null
  nullable    = true
}

variable "create_security_logs_bucket" {
  description = "Whether to create a dedicated S3 bucket for security service logs."
  type        = bool
  default     = true
}

variable "security_logs_bucket_name" {
  description = "Optional existing S3 bucket name for CloudTrail and Config delivery."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = !(
      var.enable_cloudtrail || var.enable_config
    ) || var.create_security_logs_bucket || var.security_logs_bucket_name != null
    error_message = "Set security_logs_bucket_name when create_security_logs_bucket is false and CloudTrail or Config is enabled."
  }
}

variable "security_logs_bucket_force_destroy" {
  description = "Whether the managed security logs bucket may be force-destroyed."
  type        = bool
  default     = false
}

variable "cloudtrail_log_retention_in_days" {
  description = "Retention in days for the CloudTrail CloudWatch log group."
  type        = number
  default     = 90
}

variable "flow_logs_log_retention_in_days" {
  description = "Retention in days for VPC Flow Logs CloudWatch log group."
  type        = number
  default     = 90
}

variable "enable_cloudtrail" {
  description = "Whether to manage CloudTrail."
  type        = bool
  default     = false
}

variable "enable_config" {
  description = "Whether to manage AWS Config recorder and selected rules."
  type        = bool
  default     = false
}

variable "enable_config_rules" {
  description = "Whether to manage selected AWS Config rules in addition to the recorder and delivery channel."
  type        = bool
  default     = false
}

variable "enable_securityhub" {
  description = "Whether to manage Security Hub and FSBP."
  type        = bool
  default     = false
}

variable "enable_guardduty" {
  description = "Whether to manage GuardDuty."
  type        = bool
  default     = false
}

variable "guardduty_finding_publishing_frequency" {
  description = "Finding publishing frequency for GuardDuty."
  type        = string
  default     = "SIX_HOURS"

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_finding_publishing_frequency)
    error_message = "guardduty_finding_publishing_frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

variable "enable_ecr_registry_scan" {
  description = "Whether to manage account-level ECR scanning."
  type        = bool
  default     = false
}

variable "enable_flow_logs" {
  description = "Whether to manage VPC Flow Logs for managed_vpc_ids."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_flow_logs || length(var.managed_vpc_ids) > 0
    error_message = "managed_vpc_ids must be set when enable_flow_logs is true."
  }
}

variable "enable_waf" {
  description = "Whether this stack should later own the existing WAF resources."
  type        = bool
  default     = false
}

variable "enable_incident_response" {
  description = "Whether to manage SSM Incident Manager response plans."
  type        = bool
  default     = false
}

variable "managed_vpc_ids" {
  description = "VPC IDs that should receive security baseline resources such as flow logs."
  type        = list(string)
  default     = []
}

variable "flow_log_traffic_type" {
  description = "Traffic type to capture in VPC Flow Logs."
  type        = string
  default     = "ALL"

  validation {
    condition     = contains(["ACCEPT", "REJECT", "ALL"], var.flow_log_traffic_type)
    error_message = "flow_log_traffic_type must be ACCEPT, REJECT, or ALL."
  }
}

variable "create_flow_logs_log_group" {
  description = "Whether to create a dedicated CloudWatch log group for VPC Flow Logs."
  type        = bool
  default     = false
}

variable "flow_logs_log_group_name" {
  description = "Existing or desired CloudWatch log group name for VPC Flow Logs."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = !var.enable_flow_logs || var.create_flow_logs_log_group || var.flow_logs_log_group_name != null
    error_message = "Set flow_logs_log_group_name when enable_flow_logs is true and create_flow_logs_log_group is false."
  }
}

variable "create_flow_logs_iam_role" {
  description = "Whether to create a dedicated IAM role for VPC Flow Logs."
  type        = bool
  default     = false
}

variable "flow_logs_role_arn" {
  description = "Existing IAM role ARN for VPC Flow Logs when create_flow_logs_iam_role is false."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = !var.enable_flow_logs || var.create_flow_logs_iam_role || var.flow_logs_role_arn != null
    error_message = "Set flow_logs_role_arn when enable_flow_logs is true and create_flow_logs_iam_role is false."
  }
}

variable "flow_log_tags" {
  description = "Explicit tags for Flow Log resources. Leave empty to use the common tag set."
  type        = map(string)
  default     = {}
}

variable "config_recorder_name" {
  description = "AWS Config recorder name."
  type        = string
  default     = "default"
}

variable "config_delivery_channel_name" {
  description = "AWS Config delivery channel name."
  type        = string
  default     = "default"
}

variable "create_config_service_role" {
  description = "Whether to create a dedicated IAM role for AWS Config instead of reusing an existing service-linked role."
  type        = bool
  default     = false
}

variable "config_recorder_role_arn" {
  description = "Existing AWS Config recorder role ARN when create_config_service_role is false."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = !var.enable_config || var.create_config_service_role || var.config_recorder_role_arn != null
    error_message = "Set config_recorder_role_arn when enable_config is true and create_config_service_role is false."
  }
}

variable "config_rule_names" {
  description = "Selected AWS managed Config rules to create."
  type        = list(string)
  default = [
    "cloudtrail-enabled",
    "cloud-trail-cloud-watch-logs-enabled",
    "vpc-default-security-group-closed",
    "rds-instance-public-access-check",
    "db-instance-backup-enabled",
    "cmk-backing-key-rotation-enabled"
  ]
}

variable "existing_waf_web_acl_arn" {
  description = "Existing WAF Web ACL ARN to import later."
  type        = string
  default     = null
  nullable    = true
}

variable "incident_response_plan_name" {
  description = "Name of the basic SSM response plan."
  type        = string
  default     = "basic-response"
}

variable "incident_response_plan_display_name" {
  description = "Display name of the basic SSM response plan."
  type        = string
  default     = "basic-response"
}

variable "incident_response_impact" {
  description = "Default incident impact for the basic response plan."
  type        = number
  default     = 5
}
