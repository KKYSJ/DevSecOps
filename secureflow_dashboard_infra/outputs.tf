output "alb_dns_name" {
  description = "Public ALB DNS."
  value       = aws_lb.main.dns_name
}

output "cloudfront_domain_name" {
  description = "CloudFront domain name when enable_cloudfront_https is true."
  value       = try(aws_cloudfront_distribution.app[0].domain_name, null)
}

output "alb_frontend_url" {
  description = "Direct ALB frontend URL."
  value       = var.acm_certificate_arn != null ? "https://${aws_lb.main.dns_name}" : "http://${aws_lb.main.dns_name}"
}

output "frontend_url" {
  description = "Preferred frontend URL. Uses CloudFront HTTPS when enabled."
  value       = var.enable_cloudfront_https ? "https://${aws_cloudfront_distribution.app[0].domain_name}" : (var.acm_certificate_arn != null ? "https://${aws_lb.main.dns_name}" : "http://${aws_lb.main.dns_name}")
}

output "backend_api_url" {
  description = "Preferred backend API URL. Uses CloudFront HTTPS when enabled."
  value       = var.enable_cloudfront_https ? "https://${aws_cloudfront_distribution.app[0].domain_name}/api/v1" : (var.acm_certificate_arn != null ? "https://${aws_lb.main.dns_name}/api/v1" : "http://${aws_lb.main.dns_name}/api/v1")
}

output "ecs_cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.main.name
}

output "frontend_service_name" {
  description = "Frontend ECS service name."
  value       = aws_ecs_service.frontend.name
}

output "backend_service_name" {
  description = "Backend ECS service name."
  value       = aws_ecs_service.backend.name
}

output "worker_service_name" {
  description = "Worker ECS service name."
  value       = aws_ecs_service.worker.name
}

output "frontend_ecr_repository_url" {
  description = "Frontend ECR repository URL."
  value       = aws_ecr_repository.frontend.repository_url
}

output "backend_ecr_repository_url" {
  description = "Backend ECR repository URL."
  value       = aws_ecr_repository.backend.repository_url
}

output "worker_ecr_repository_url" {
  description = "Worker ECR repository URL."
  value       = aws_ecr_repository.worker.repository_url
}

output "reports_bucket_name" {
  description = "Reports bucket name."
  value       = aws_s3_bucket.reports.id
}

output "db_secret_arn" {
  description = "Database runtime Secrets Manager ARN."
  value       = aws_secretsmanager_secret.db.arn
  sensitive   = true
}

output "redis_secret_arn" {
  description = "Redis runtime Secrets Manager ARN."
  value       = aws_secretsmanager_secret.redis.arn
  sensitive   = true
}

output "external_api_secret_arn" {
  description = "External API Secrets Manager ARN. Populate this outside Terraform to keep real API keys out of state."
  value       = aws_secretsmanager_secret.external_api.arn
  sensitive   = true
}

output "external_api_secret_template" {
  description = "JSON template for the external API secret."
  value = jsonencode({
    GEMINI_API_KEY = "set-me"
    OPENAI_API_KEY = "set-me-or-empty"
    SONAR_TOKEN    = "set-me"
  })
}

output "rds_endpoint" {
  description = "RDS endpoint."
  value       = aws_db_instance.postgres.address
}

output "redis_endpoint" {
  description = "Redis primary endpoint."
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "github_secret_backend_url" {
  description = "Value to store in the GitHub secret API_SERVER_URL."
  value       = var.enable_cloudfront_https ? "https://${aws_cloudfront_distribution.app[0].domain_name}/api/v1" : (var.acm_certificate_arn != null ? "https://${aws_lb.main.dns_name}/api/v1" : "http://${aws_lb.main.dns_name}/api/v1")
}

output "github_repository_variables" {
  description = "Suggested GitHub repository variable values for this stack."
  value = {
    AWS_ACCOUNT_ID          = data.aws_caller_identity.current.account_id
    AWS_REGION              = var.aws_region
    DAST_STAGING_TARGET_URL = var.enable_cloudfront_https ? "https://${aws_cloudfront_distribution.app[0].domain_name}" : (var.acm_certificate_arn != null ? "https://${aws_lb.main.dns_name}" : "http://${aws_lb.main.dns_name}")
    GEMINI_MODEL            = var.gemini_model
    SONAR_HOST_URL          = var.sonar_host_url
    SONAR_ORGANIZATION      = var.sonar_organization
    SONAR_PROJECT_KEY       = var.sonar_project_key
  }
}
