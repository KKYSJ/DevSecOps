variable "service_name" {
  description = "ECS service name and task family prefix."
  type        = string
}

variable "cluster_arn" {
  description = "ECS cluster ARN."
  type        = string
}

variable "subnet_ids" {
  description = "Subnets used by the ECS service."
  type        = list(string)
}

variable "security_group_ids" {
  description = "Security groups attached to the ECS tasks."
  type        = list(string)
}

variable "target_group_arn" {
  description = "Target group ARN for the service."
  type        = string
}

variable "container_name" {
  description = "Container name exposed in the task definition."
  type        = string
}

variable "container_image" {
  description = "Full container image URI."
  type        = string
}

variable "container_port" {
  description = "Container port exposed by the application."
  type        = number
}

variable "cpu" {
  description = "Task CPU units."
  type        = number
  default     = 512
}

variable "memory" {
  description = "Task memory in MiB."
  type        = number
  default     = 1024
}

variable "desired_count" {
  description = "Desired task count."
  type        = number
  default     = 1
}

variable "assign_public_ip" {
  description = "Whether to assign a public IP to the task ENI."
  type        = bool
  default     = false
}

variable "health_check_grace_period_seconds" {
  description = "Grace period before ALB health checks affect the service."
  type        = number
  default     = 60
}

variable "execution_role_arn" {
  description = "ECS task execution role ARN."
  type        = string
}

variable "task_role_arn" {
  description = "Application task role ARN."
  type        = string
}

variable "log_group_name" {
  description = "CloudWatch Logs group name."
  type        = string
}

variable "aws_region" {
  description = "AWS region used by the awslogs driver."
  type        = string
}

variable "environment_variables" {
  description = "Plaintext environment variables passed to the container."
  type        = map(string)
  default     = {}
}

variable "secret_environment_variables" {
  description = "Sensitive environment variables passed from Secrets Manager or SSM."
  type        = map(string)
  default     = {}
}

variable "readonly_root_filesystem" {
  description = "Whether the container root filesystem should be mounted read-only."
  type        = bool
  default     = false
}

variable "mount_points" {
  description = "Writable mount points attached to the container."
  type = list(object({
    source_volume  = string
    container_path = string
    read_only      = optional(bool, false)
  }))
  default = []
}

variable "volumes" {
  description = "Task-level ephemeral volumes that can be mounted by containers."
  type = list(object({
    name = string
  }))
  default = []
}

variable "tags" {
  description = "Tags applied to the ECS service resources."
  type        = map(string)
  default     = {}
}
