variable "project_name" {
  description = "Project name used in log group paths."
  type        = string
}

variable "environment" {
  description = "Environment used in log group paths."
  type        = string
}

variable "service_names" {
  description = "Application services that should have CloudWatch log groups."
  type        = list(string)
}

variable "log_retention_in_days" {
  description = "CloudWatch Logs retention in days."
  type        = number
  default     = 30
}

variable "create_alerts_topic" {
  description = "Whether to create an SNS topic for future infrastructure alarms."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags applied to monitoring resources."
  type        = map(string)
  default     = {}
}
