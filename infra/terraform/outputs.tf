output "vpc_id" {
  description = "VPC ID for the shared application network."
  value       = module.vpc.vpc_id
}

output "public_subnet_ids" {
  description = "Public subnet IDs."
  value       = module.vpc.public_subnet_ids
}

output "private_app_subnet_ids" {
  description = "Private app subnet IDs."
  value       = module.vpc.private_app_subnet_ids
}

output "private_data_subnet_ids" {
  description = "Private data subnet IDs."
  value       = module.vpc.private_data_subnet_ids
}

output "alb_dns_name" {
  description = "Public DNS name of the application load balancer."
  value       = module.alb.dns_name
}

output "alb_target_group_arns" {
  description = "Target groups prepared for the API services."
  value       = module.alb.target_group_arns
}

output "ecs_cluster_name" {
  description = "ECS cluster name."
  value       = module.ecs.cluster_name
}

output "ecr_repository_urls" {
  description = "ECR repositories to push service images into."
  value       = local.ecr_repository_urls
}

output "frontend_bucket_name" {
  description = "Bucket for static frontend assets."
  value       = module.s3.frontend_bucket_name
}

output "uploads_bucket_name" {
  description = "Bucket for application uploads."
  value       = module.s3.uploads_bucket_name
}

output "reviews_table_name" {
  description = "DynamoDB table used for reviews."
  value       = aws_dynamodb_table.reviews.name
}

output "orders_queue_url" {
  description = "SQS queue URL for asynchronous order events."
  value       = aws_sqs_queue.orders.url
}

output "orders_topic_arn" {
  description = "SNS topic ARN for notifications."
  value       = aws_sns_topic.orders.arn
}

output "kms_key_arn" {
  description = "KMS key ARN for future application use."
  value       = module.iam_kms.kms_key_arn
}

output "github_actions_role_arn" {
  description = "Optional GitHub Actions OIDC deployment role ARN."
  value       = module.iam_kms.github_actions_role_arn
}

output "ecs_execution_role_arn" {
  description = "IAM role ARN for ECS task execution."
  value       = module.iam_kms.ecs_execution_role_arn
}

output "ecs_task_role_arn" {
  description = "IAM role ARN for ECS application tasks."
  value       = module.iam_kms.ecs_task_role_arn
}

output "rds_endpoint" {
  description = "RDS endpoint if create_rds is enabled."
  value       = try(module.rds[0].endpoint, null)
}

output "rds_secret_arn" {
  description = "Secrets Manager ARN for RDS credentials if create_rds is enabled."
  value       = try(module.rds[0].secret_arn, null)
}

output "fastapi_image_uri" {
  description = "FastAPI image URI expected by the ECS service."
  value       = local.fastapi_image_uri
}

output "node_image_uri" {
  description = "Node image URI expected by the ECS service."
  value       = local.node_image_uri
}

output "node_service_name" {
  description = "ECS service name for Node when enabled."
  value       = try(module.node_service[0].service_name, null)
}

output "node_task_definition_arn" {
  description = "Task definition ARN for Node when enabled."
  value       = try(module.node_service[0].task_definition_arn, null)
}

output "node_jwt_secret_arn" {
  description = "Secrets Manager ARN holding the shared JWT secret when APIs are enabled."
  value       = try(aws_secretsmanager_secret.shared_jwt[0].arn, null)
}

output "spring_image_uri" {
  description = "Spring image URI expected by the ECS service."
  value       = local.spring_image_uri
}

output "spring_service_name" {
  description = "ECS service name for Spring when enabled."
  value       = try(module.spring_service[0].service_name, null)
}

output "spring_task_definition_arn" {
  description = "Task definition ARN for Spring when enabled."
  value       = try(module.spring_service[0].task_definition_arn, null)
}

output "spring_jwt_secret_arn" {
  description = "Secrets Manager ARN holding the shared JWT secret when APIs are enabled."
  value       = try(aws_secretsmanager_secret.shared_jwt[0].arn, null)
}

output "frontend_image_uri" {
  description = "Frontend image URI expected by the ECS service."
  value       = local.frontend_image_uri
}

output "frontend_service_name" {
  description = "ECS service name for the frontend when enabled."
  value       = try(module.frontend_service[0].service_name, null)
}

output "frontend_task_definition_arn" {
  description = "Task definition ARN for the frontend when enabled."
  value       = try(module.frontend_service[0].task_definition_arn, null)
}

output "fastapi_service_name" {
  description = "ECS service name for FastAPI when enabled."
  value       = try(module.fastapi_service[0].service_name, null)
}

output "fastapi_task_definition_arn" {
  description = "Task definition ARN for FastAPI when enabled."
  value       = try(module.fastapi_service[0].task_definition_arn, null)
}

output "fastapi_jwt_secret_arn" {
  description = "Secrets Manager ARN holding the shared JWT secret when APIs are enabled."
  value       = try(aws_secretsmanager_secret.shared_jwt[0].arn, null)
}

output "shared_jwt_secret_arn" {
  description = "Secrets Manager ARN holding the shared JWT secret used by the API services."
  value       = try(aws_secretsmanager_secret.shared_jwt[0].arn, null)
}
