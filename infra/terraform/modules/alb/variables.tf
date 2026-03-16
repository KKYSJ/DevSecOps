variable "name" {
  description = "Name of the application load balancer."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where the ALB target groups live."
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnet IDs used by the ALB."
  type        = list(string)
}

variable "security_group_ids" {
  description = "Security groups attached to the ALB."
  type        = list(string)
}

variable "service_target_groups" {
  description = "Target groups prepared for application services."
  type = map(object({
    port              = number
    health_check_path = string
  }))
}

variable "certificate_arn" {
  description = "Optional ACM certificate ARN for HTTPS."
  type        = string
  default     = null
  nullable    = true
}

variable "tags" {
  description = "Tags applied to ALB resources."
  type        = map(string)
  default     = {}
}
