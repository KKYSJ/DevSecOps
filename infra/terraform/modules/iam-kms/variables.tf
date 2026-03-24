variable "project_name" {
  description = "Project name used for IAM and KMS resource names."
  type        = string
}

variable "environment" {
  description = "Environment name used for IAM and KMS resource names."
  type        = string
}

variable "create_github_oidc_role" {
  description = "Whether to create a GitHub Actions OIDC role."
  type        = bool
  default     = false
}

variable "create_github_oidc_provider" {
  description = "Whether to create the shared GitHub Actions OIDC provider."
  type        = bool
  default     = true
}

variable "github_org" {
  description = "GitHub organization or user name."
  type        = string
  default     = ""
}

variable "github_repo" {
  description = "GitHub repository name."
  type        = string
  default     = ""
}

variable "github_branch" {
  description = "GitHub branch allowed to assume the deployment role."
  type        = string
  default     = "main"
}

variable "github_oidc_subjects" {
  description = "Optional explicit OIDC subjects allowed to assume the role."
  type        = list(string)
  default     = []
}

variable "github_oidc_thumbprints" {
  description = "Thumbprints used by the GitHub OIDC provider."
  type        = list(string)
  default     = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

variable "ecr_repository_arns" {
  description = "ECR repositories that the GitHub Actions role may push to."
  type        = list(string)
  default     = []
}

variable "frontend_bucket_arn" {
  description = "Optional frontend bucket ARN for deployment uploads."
  type        = string
  default     = null
  nullable    = true
}

variable "uploads_bucket_arn" {
  description = "Optional uploads bucket ARN for ECS task access."
  type        = string
  default     = null
  nullable    = true
}

variable "dynamodb_table_arn" {
  description = "Optional DynamoDB table ARN for ECS task access."
  type        = string
  default     = null
  nullable    = true
}

variable "sqs_queue_arn" {
  description = "Optional SQS queue ARN for ECS task access."
  type        = string
  default     = null
  nullable    = true
}

variable "sns_topic_arn" {
  description = "Optional SNS topic ARN for ECS task access."
  type        = string
  default     = null
  nullable    = true
}

variable "tags" {
  description = "Tags applied to IAM and KMS resources."
  type        = map(string)
  default     = {}
}
