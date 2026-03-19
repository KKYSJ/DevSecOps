output "alb_dns_name" {
  description = "Public ALB DNS"
  value       = aws_lb.main.dns_name
}

output "frontend_url" {
  description = "Frontend URL"
  value       = var.acm_certificate_arn != null ? "https://${aws_lb.main.dns_name}" : "http://${aws_lb.main.dns_name}"
}

output "backend_api_url" {
  description = "Backend API base URL"
  value       = var.acm_certificate_arn != null ? "https://${aws_lb.main.dns_name}/api/v1" : "http://${aws_lb.main.dns_name}/api/v1"
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.main.name
}

output "frontend_ecr_repository_url" {
  description = "Frontend ECR repo"
  value       = aws_ecr_repository.frontend.repository_url
}

output "backend_ecr_repository_url" {
  description = "Backend ECR repo"
  value       = aws_ecr_repository.backend.repository_url
}

output "worker_ecr_repository_url" {
  description = "Worker ECR repo"
  value       = aws_ecr_repository.worker.repository_url
}

output "reports_bucket_name" {
  description = "Reports bucket"
  value       = aws_s3_bucket.reports.id
}

output "app_secret_arn" {
  description = "App secret ARN"
  value       = aws_secretsmanager_secret.app.arn
  sensitive   = true
}

output "rds_endpoint" {
  description = "RDS endpoint"
  value       = aws_db_instance.postgres.address
}

output "redis_endpoint" {
  description = "Redis primary endpoint"
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
}
