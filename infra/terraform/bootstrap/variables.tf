variable "project_name" {
  description = "Project prefix for bootstrap resources."
  type        = string
  default     = "secureflow"
}

variable "environment" {
  description = "Environment for the bootstrap state resources."
  type        = string
  default     = "shared"
}

variable "aws_region" {
  description = "AWS region where the Terraform backend resources will live."
  type        = string
}

variable "state_bucket_name" {
  description = "Optional explicit name for the Terraform state bucket."
  type        = string
  default     = null
  nullable    = true
}

variable "lock_table_name" {
  description = "Optional explicit name for the Terraform lock table."
  type        = string
  default     = null
  nullable    = true
}

variable "force_destroy" {
  description = "Whether Terraform may destroy the state bucket contents."
  type        = bool
  default     = false
}

variable "default_tags" {
  description = "Additional tags applied to bootstrap resources."
  type        = map(string)
  default     = {}
}
