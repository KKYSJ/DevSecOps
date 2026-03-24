variable "bucket_prefix" {
  description = "Project prefix used in generated bucket names."
  type        = string
}

variable "environment" {
  description = "Environment name appended to generated bucket names."
  type        = string
}

variable "frontend_bucket_name" {
  description = "Optional explicit name for the frontend bucket."
  type        = string
  default     = null
  nullable    = true
}

variable "uploads_bucket_name" {
  description = "Optional explicit name for the uploads bucket."
  type        = string
  default     = null
  nullable    = true
}

variable "create_frontend_bucket" {
  description = "Whether to create the frontend bucket."
  type        = bool
  default     = true
}

variable "create_uploads_bucket" {
  description = "Whether to create the uploads bucket."
  type        = bool
  default     = true
}

variable "frontend_cors_allowed_origins" {
  description = "Origins allowed to upload directly to the uploads bucket."
  type        = list(string)
  default     = []
}

variable "kms_key_arn" {
  description = "Optional KMS key ARN for S3 encryption."
  type        = string
  default     = null
  nullable    = true
}

variable "force_destroy" {
  description = "Allow Terraform to destroy non-empty buckets."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to bucket resources."
  type        = map(string)
  default     = {}
}
