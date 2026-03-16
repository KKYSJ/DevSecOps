variable "name" {
  description = "ECS cluster name."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for optional private service discovery."
  type        = string
}

variable "create_service_discovery_namespace" {
  description = "Whether to create a private Cloud Map namespace."
  type        = bool
  default     = true
}

variable "service_discovery_namespace_name" {
  description = "Name of the private service discovery namespace."
  type        = string
  default     = "app.local"
}

variable "enable_container_insights" {
  description = "Enable CloudWatch Container Insights on the cluster."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags applied to ECS resources."
  type        = map(string)
  default     = {}
}
