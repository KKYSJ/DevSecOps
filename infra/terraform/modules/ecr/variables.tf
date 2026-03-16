variable "repositories" {
  description = "ECR repositories to create."
  type = map(object({
    image_tag_mutability = optional(string, "IMMUTABLE")
    scan_on_push         = optional(bool, true)
    lifecycle_max_images = optional(number, 30)
  }))
}

variable "kms_key_arn" {
  description = "Optional KMS key ARN for ECR encryption."
  type        = string
  default     = null
  nullable    = true
}

variable "force_delete" {
  description = "Allow deleting repositories with images."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to repositories."
  type        = map(string)
  default     = {}
}
