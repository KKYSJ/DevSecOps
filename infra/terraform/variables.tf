variable "project_name" {
  description = "Project prefix used across AWS resources."
  type        = string
  default     = "secureflow"
}

variable "environment" {
  description = "Deployment environment name such as dev or prod."
  type        = string
}

variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
}

variable "availability_zones" {
  description = "Optional list of AZs to use. Leave empty to auto-select the first two available."
  type        = list(string)
  default     = []
}

variable "vpc_cidr" {
  description = "CIDR block for the shared VPC."
  type        = string
  default     = "10.20.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDRs for public subnets."
  type        = list(string)
  default     = ["10.20.0.0/24", "10.20.1.0/24"]
}

variable "private_app_subnet_cidrs" {
  description = "CIDRs for private application subnets."
  type        = list(string)
  default     = ["10.20.10.0/24", "10.20.11.0/24"]
}

variable "private_data_subnet_cidrs" {
  description = "CIDRs for private data subnets."
  type        = list(string)
  default     = ["10.20.20.0/24", "10.20.21.0/24"]
}

variable "single_nat_gateway" {
  description = "Use a single NAT gateway to lower cost in non-production environments."
  type        = bool
  default     = true
}

variable "allowed_ingress_cidrs" {
  description = "CIDR ranges allowed to reach the public ALB."
  type        = list(string)
  default     = ["0.0.0.0/0"]
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

variable "frontend_allowed_origins" {
  description = "Origins allowed for uploads bucket CORS."
  type        = list(string)
  default     = []
}

variable "reviews_table_name" {
  description = "Optional explicit name for the DynamoDB reviews table."
  type        = string
  default     = null
  nullable    = true
}

variable "review_table_hash_key_type" {
  description = "Hash key type for productId in the reviews table. Use S for Node/FastAPI and N for Spring if you keep its current code."
  type        = string
  default     = "S"

  validation {
    condition     = contains(["S", "N"], var.review_table_hash_key_type)
    error_message = "review_table_hash_key_type must be either S or N."
  }
}

variable "orders_queue_name" {
  description = "Optional explicit name for the orders SQS queue."
  type        = string
  default     = null
  nullable    = true
}

variable "orders_topic_name" {
  description = "Optional explicit name for the orders SNS topic."
  type        = string
  default     = null
  nullable    = true
}

variable "create_rds" {
  description = "Whether to provision the MySQL RDS instance now."
  type        = bool
  default     = false
}

variable "db_name" {
  description = "Application database name."
  type        = string
  default     = "secureflow"
}

variable "db_username" {
  description = "Master username for the MySQL instance."
  type        = string
  default     = "secureflow"
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  description = "RDS allocated storage in GiB."
  type        = number
  default     = 20
}

variable "db_engine_version" {
  description = "Optional explicit MySQL engine version."
  type        = string
  default     = null
  nullable    = true
}

variable "db_multi_az" {
  description = "Enable Multi-AZ for the RDS instance."
  type        = bool
  default     = false
}

variable "db_backup_retention_period" {
  description = "Backup retention period for RDS."
  type        = number
  default     = 7
}

variable "db_deletion_protection" {
  description = "Whether to enable deletion protection for RDS."
  type        = bool
  default     = false
}

variable "db_skip_final_snapshot" {
  description = "Whether to skip the final snapshot when deleting RDS."
  type        = bool
  default     = true
}

variable "log_retention_in_days" {
  description = "CloudWatch log retention for ECS workloads."
  type        = number
  default     = 30
}

variable "acm_certificate_arn" {
  description = "Optional ACM certificate ARN for enabling HTTPS on the ALB."
  type        = string
  default     = null
  nullable    = true
}

variable "create_github_oidc_role" {
  description = "Whether to create a GitHub Actions OIDC deployment role."
  type        = bool
  default     = false
}

variable "create_github_oidc_provider" {
  description = "Whether to create the shared GitHub Actions OIDC provider. Disable this when the account already has one."
  type        = bool
  default     = true
}

variable "create_ecr_repositories" {
  description = "Whether to create shared ECR repositories. Disable this when they already exist in the AWS account."
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
  description = "Branch allowed to assume the GitHub deployment role."
  type        = string
  default     = "main"
}

variable "github_oidc_subjects" {
  description = "Optional explicit subject filters for the GitHub OIDC trust policy."
  type        = list(string)
  default     = []
}

variable "github_oidc_thumbprints" {
  description = "Thumbprints used for the GitHub OIDC provider."
  type        = list(string)
  default     = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

variable "default_tags" {
  description = "Additional tags applied to all resources."
  type        = map(string)
  default     = {}
}

variable "enable_fastapi_service" {
  description = "Whether to create the ECS service for the FastAPI application."
  type        = bool
  default     = false
}

variable "fastapi_image_tag" {
  description = "Container image tag for the FastAPI service."
  type        = string
  default     = "latest"
}

variable "fastapi_desired_count" {
  description = "Desired task count for the FastAPI ECS service."
  type        = number
  default     = 1
}

variable "fastapi_cpu" {
  description = "CPU units for the FastAPI task definition."
  type        = number
  default     = 512
}

variable "fastapi_memory" {
  description = "Memory in MiB for the FastAPI task definition."
  type        = number
  default     = 1024
}

variable "fastapi_assign_public_ip" {
  description = "Whether the FastAPI task should receive a public IP."
  type        = bool
  default     = false
}

variable "fastapi_path_patterns" {
  description = "Listener path patterns routed to the FastAPI service."
  type        = list(string)
  default = [
    "/api/products/*/reviews*",
    "/api/upload*",
    "/uploads*",
    "/api/health",
    "/api/config",
  ]
}

variable "fastapi_jwt_secret_name" {
  description = "Optional explicit secret name for the FastAPI JWT secret."
  type        = string
  default     = null
  nullable    = true
}

variable "shared_jwt_secret_name" {
  description = "Optional explicit secret name for the shared API JWT secret."
  type        = string
  default     = null
  nullable    = true
}

variable "fastapi_environment_overrides" {
  description = "Optional extra environment variables for the FastAPI container."
  type        = map(string)
  default     = {}
}

variable "enable_node_service" {
  description = "Whether to create the ECS service for the Node application."
  type        = bool
  default     = false
}

variable "node_image_tag" {
  description = "Container image tag for the Node service."
  type        = string
  default     = "latest"
}

variable "node_desired_count" {
  description = "Desired task count for the Node ECS service."
  type        = number
  default     = 1
}

variable "node_cpu" {
  description = "CPU units for the Node task definition."
  type        = number
  default     = 512
}

variable "node_memory" {
  description = "Memory in MiB for the Node task definition."
  type        = number
  default     = 1024
}

variable "node_assign_public_ip" {
  description = "Whether the Node task should receive a public IP."
  type        = bool
  default     = false
}

variable "node_use_rds" {
  description = "When create_rds is enabled, configure the Node service to use MySQL for persistent auth/cart/order data."
  type        = bool
  default     = true
}

variable "node_path_patterns" {
  description = "Listener path patterns routed to the Node service."
  type        = list(string)
  default = [
    "/api/auth*",
    "/api/cart*",
    "/api/orders*",
  ]
}

variable "node_jwt_secret_name" {
  description = "Optional explicit secret name for the Node JWT secret."
  type        = string
  default     = null
  nullable    = true
}

variable "node_environment_overrides" {
  description = "Optional extra environment variables for the Node container."
  type        = map(string)
  default     = {}
}

variable "enable_spring_service" {
  description = "Whether to create the ECS service for the Spring application."
  type        = bool
  default     = false
}

variable "spring_image_tag" {
  description = "Container image tag for the Spring service."
  type        = string
  default     = "latest"
}

variable "spring_desired_count" {
  description = "Desired task count for the Spring ECS service."
  type        = number
  default     = 1
}

variable "spring_cpu" {
  description = "CPU units for the Spring task definition."
  type        = number
  default     = 512
}

variable "spring_memory" {
  description = "Memory in MiB for the Spring task definition."
  type        = number
  default     = 1024
}

variable "spring_assign_public_ip" {
  description = "Whether the Spring task should receive a public IP."
  type        = bool
  default     = false
}

variable "spring_path_patterns" {
  description = "Listener path patterns routed to the Spring service."
  type        = list(string)
  default = [
    "/api/products*",
  ]
}

variable "spring_jwt_secret_name" {
  description = "Optional explicit secret name for the Spring JWT secret."
  type        = string
  default     = null
  nullable    = true
}

variable "spring_environment_overrides" {
  description = "Optional extra environment variables for the Spring container."
  type        = map(string)
  default     = {}
}

variable "enable_frontend_service" {
  description = "Whether to create the ECS service for the frontend application."
  type        = bool
  default     = false
}

variable "frontend_image_tag" {
  description = "Container image tag for the frontend service."
  type        = string
  default     = "latest"
}

variable "frontend_desired_count" {
  description = "Desired task count for the frontend ECS service."
  type        = number
  default     = 1
}

variable "frontend_cpu" {
  description = "CPU units for the frontend task definition."
  type        = number
  default     = 256
}

variable "frontend_memory" {
  description = "Memory in MiB for the frontend task definition."
  type        = number
  default     = 512
}

variable "frontend_assign_public_ip" {
  description = "Whether the frontend task should receive a public IP."
  type        = bool
  default     = false
}

variable "frontend_path_patterns" {
  description = "Listener path patterns routed to the frontend service."
  type        = list(string)
  default     = ["/", "/*"]
}
