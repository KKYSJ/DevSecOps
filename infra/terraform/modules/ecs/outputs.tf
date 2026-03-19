output "cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.this.name
}

output "cluster_arn" {
  description = "ECS cluster ARN."
  value       = aws_ecs_cluster.this.arn
}

output "service_discovery_namespace_id" {
  description = "Cloud Map namespace ID when created."
  value       = try(aws_service_discovery_private_dns_namespace.this[0].id, null)
}

output "service_discovery_namespace_arn" {
  description = "Cloud Map namespace ARN when created."
  value       = try(aws_service_discovery_private_dns_namespace.this[0].arn, null)
}
