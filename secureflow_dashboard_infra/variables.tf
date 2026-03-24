variable "project_name" {
  description = "Project prefix used across AWS resources."
  type        = string
  default     = "secureflow-dashboard"
}

variable "environment" {
  description = "Deployment environment such as dev, stage, or prod."
  type        = string
  default     = "dev"
}

variable "managed_by" {
  description = "Operator or owner label stored in resource tags."
  type        = string
  default     = "admin-dev"
}

variable "aws_region" {
  description = "AWS region."
  type        = string
  default     = "ap-northeast-2"
}

variable "vpc_cidr" {
  description = "VPC CIDR."
  type        = string
  default     = "10.50.0.0/16"
}

variable "frontend_image_tag" {
  description = "Frontend image tag."
  type        = string
  default     = "latest"
}

variable "backend_image_tag" {
  description = "Backend image tag."
  type        = string
  default     = "latest"
}

variable "worker_image_tag" {
  description = "Worker image tag."
  type        = string
  default     = "latest"
}

variable "frontend_cpu" {
  description = "Frontend task CPU units."
  type        = number
  default     = 256
}

variable "frontend_memory" {
  description = "Frontend task memory in MiB."
  type        = number
  default     = 512
}

variable "backend_cpu" {
  description = "Backend task CPU units."
  type        = number
  default     = 512
}

variable "backend_memory" {
  description = "Backend task memory in MiB."
  type        = number
  default     = 1024
}

variable "worker_cpu" {
  description = "Worker task CPU units."
  type        = number
  default     = 512
}

variable "worker_memory" {
  description = "Worker task memory in MiB."
  type        = number
  default     = 1024
}

variable "frontend_desired_count" {
  description = "Frontend desired count."
  type        = number
  default     = 1
}

variable "backend_desired_count" {
  description = "Backend desired count."
  type        = number
  default     = 1
}

variable "worker_desired_count" {
  description = "Worker desired count."
  type        = number
  default     = 1
}

variable "frontend_min_capacity" {
  description = "Frontend autoscaling minimum."
  type        = number
  default     = 1
}

variable "frontend_max_capacity" {
  description = "Frontend autoscaling maximum."
  type        = number
  default     = 2
}

variable "backend_min_capacity" {
  description = "Backend autoscaling minimum."
  type        = number
  default     = 1
}

variable "backend_max_capacity" {
  description = "Backend autoscaling maximum."
  type        = number
  default     = 2
}

variable "enable_autoscaling" {
  description = "Whether to enable frontend and backend ECS autoscaling."
  type        = bool
  default     = false
}

variable "cpu_scale_target" {
  description = "Target ECS CPU utilization percentage for autoscaling."
  type        = number
  default     = 60
}

variable "db_name" {
  description = "PostgreSQL database name."
  type        = string
  default     = "secureflow_dashboard"
}

variable "db_username" {
  description = "PostgreSQL master username. RDS does not allow hyphens, so admin_dev is used instead of admin-dev."
  type        = string
  default     = "admin_dev"
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  description = "Initial RDS storage in GiB."
  type        = number
  default     = 20
}

variable "db_max_allocated_storage" {
  description = "Maximum RDS autoscaling storage in GiB."
  type        = number
  default     = 100
}

variable "db_engine_version" {
  description = "PostgreSQL engine version."
  type        = string
  default     = "16.6"
}

variable "db_backup_retention_period" {
  description = "RDS backup retention period in days."
  type        = number
  default     = 7
}

variable "db_multi_az" {
  description = "Whether to enable Multi-AZ for RDS."
  type        = bool
  default     = false
}

variable "redis_node_type" {
  description = "ElastiCache Redis node type."
  type        = string
  default     = "cache.t4g.micro"
}

variable "redis_engine_version" {
  description = "Redis engine version."
  type        = string
  default     = "7.1"
}

variable "reports_bucket_name" {
  description = "Optional explicit reports bucket name."
  type        = string
  default     = null
}

variable "app_secret_name" {
  description = "Deprecated alias for external_api_secret_name."
  type        = string
  default     = null
}

variable "db_secret_name" {
  description = "Optional explicit database runtime secret name."
  type        = string
  default     = null
}

variable "redis_secret_name" {
  description = "Optional explicit Redis runtime secret name."
  type        = string
  default     = null
}

variable "external_api_secret_name" {
  description = "Optional explicit external API secret name."
  type        = string
  default     = null
}

variable "gemini_api_key" {
  description = "Optional bootstrap value for the external API secret. Leaving this null keeps the real key out of Terraform state."
  type        = string
  sensitive   = true
  default     = null
}

variable "gemini_model" {
  description = "Gemini model name. This should match the GitHub repository variable GEMINI_MODEL."
  type        = string
  default     = "gemini-2.5-flash"
}

variable "openai_api_key" {
  description = "Optional bootstrap value for the external API secret. Leaving this null keeps the real key out of Terraform state."
  type        = string
  sensitive   = true
  default     = null
}

variable "sonar_host_url" {
  description = "Sonar host URL. This should match the GitHub repository variable SONAR_HOST_URL."
  type        = string
  default     = ""
}

variable "sonar_token" {
  description = "Optional bootstrap value for the external API secret. Leaving this null keeps the real key out of Terraform state."
  type        = string
  sensitive   = true
  default     = null
}

variable "sonar_organization" {
  description = "Sonar organization. This should match the GitHub repository variable SONAR_ORGANIZATION."
  type        = string
  default     = ""
}

variable "sonar_project_key" {
  description = "Sonar project key. This should match the GitHub repository variable SONAR_PROJECT_KEY."
  type        = string
  default     = ""
}

variable "alarm_email" {
  description = "Optional email target for CloudWatch alarms."
  type        = string
  default     = null
}

variable "log_retention_in_days" {
  description = "CloudWatch log retention period."
  type        = number
  default     = 365
}

variable "acm_certificate_arn" {
  description = "Optional ACM certificate ARN for direct ALB HTTPS."
  type        = string
  default     = null
}

variable "enable_cloudfront_https" {
  description = "Create a CloudFront distribution so the service can be reached over HTTPS without a custom domain."
  type        = bool
  default     = true
}

variable "cloudfront_price_class" {
  description = "CloudFront price class used when enable_cloudfront_https is true."
  type        = string
  default     = "PriceClass_200"

  validation {
    condition     = contains(["PriceClass_100", "PriceClass_200", "PriceClass_All"], var.cloudfront_price_class)
    error_message = "cloudfront_price_class must be PriceClass_100, PriceClass_200, or PriceClass_All."
  }
}

variable "enable_waf" {
  description = "Whether to enable WAF in front of the ALB."
  type        = bool
  default     = true
}

variable "waf_rate_limit" {
  description = "Per-IP WAF rate limit over a 5 minute window."
  type        = number
  default     = 2000
}

variable "actions_upload_bypass_key" {
  description = "Optional shared secret value for allowing GitHub Actions scan uploads through WAF when sent as the X-SecureFlow-Upload-Key header."
  type        = string
  default     = null
  sensitive   = true
}

variable "tags" {
  description = "Additional tags."
  type        = map(string)
  default     = {}
}
