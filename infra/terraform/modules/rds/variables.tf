variable "identifier" {
  description = "RDS identifier."
  type        = string
}

variable "db_name" {
  description = "Database name."
  type        = string
}

variable "username" {
  description = "Master username."
  type        = string
}

variable "instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.micro"
}

variable "allocated_storage" {
  description = "Allocated storage in GiB."
  type        = number
  default     = 20
}

variable "max_allocated_storage" {
  description = "Storage autoscaling upper bound in GiB."
  type        = number
  default     = 100
}

variable "engine_version" {
  description = "Optional explicit MySQL engine version."
  type        = string
  default     = null
  nullable    = true
}

variable "subnet_ids" {
  description = "Private subnet IDs used by the DB subnet group."
  type        = list(string)
}

variable "vpc_security_group_ids" {
  description = "Security groups attached to the DB instance."
  type        = list(string)
}

variable "multi_az" {
  description = "Enable Multi-AZ."
  type        = bool
  default     = false
}

variable "publicly_accessible" {
  description = "Whether the DB instance is publicly accessible."
  type        = bool
  default     = false
}

variable "backup_retention_period" {
  description = "Backup retention period in days."
  type        = number
  default     = 7
}

variable "deletion_protection" {
  description = "Enable deletion protection."
  type        = bool
  default     = false
}

variable "skip_final_snapshot" {
  description = "Skip the final snapshot on destroy."
  type        = bool
  default     = true
}

variable "apply_immediately" {
  description = "Apply changes immediately."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "Optional KMS key ARN for database encryption."
  type        = string
  default     = null
  nullable    = true
}

variable "tags" {
  description = "Tags applied to RDS resources."
  type        = map(string)
  default     = {}
}
