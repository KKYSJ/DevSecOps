output "vpc_id" {
  description = "VPC ID."
  value       = aws_vpc.this.id
}

output "public_subnet_ids" {
  description = "Public subnet IDs."
  value       = [for key in sort(keys(aws_subnet.public)) : aws_subnet.public[key].id]
}

output "private_app_subnet_ids" {
  description = "Private app subnet IDs."
  value       = [for key in sort(keys(aws_subnet.private_app)) : aws_subnet.private_app[key].id]
}

output "private_data_subnet_ids" {
  description = "Private data subnet IDs."
  value       = [for key in sort(keys(aws_subnet.private_data)) : aws_subnet.private_data[key].id]
}

output "alb_security_group_id" {
  description = "Security group ID for the ALB."
  value       = aws_security_group.alb.id
}

output "ecs_security_group_id" {
  description = "Security group ID for ECS services."
  value       = aws_security_group.ecs.id
}

output "rds_security_group_id" {
  description = "Security group ID for MySQL."
  value       = aws_security_group.rds.id
}

output "cache_security_group_id" {
  description = "Security group ID for Redis-compatible cache services."
  value       = aws_security_group.cache.id
}
