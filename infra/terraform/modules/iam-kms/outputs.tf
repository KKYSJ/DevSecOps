output "kms_key_arn" {
  description = "KMS key ARN."
  value       = aws_kms_key.this.arn
}

output "kms_key_id" {
  description = "KMS key ID."
  value       = aws_kms_key.this.key_id
}

output "ecs_execution_role_arn" {
  description = "ECS execution role ARN."
  value       = aws_iam_role.ecs_execution.arn
}

output "ecs_execution_role_name" {
  description = "ECS execution role name."
  value       = aws_iam_role.ecs_execution.name
}

output "ecs_task_role_arn" {
  description = "ECS task role ARN."
  value       = aws_iam_role.ecs_task.arn
}

output "ecs_task_role_name" {
  description = "ECS task role name."
  value       = aws_iam_role.ecs_task.name
}

output "github_actions_role_arn" {
  description = "GitHub Actions OIDC role ARN when created."
  value       = try(aws_iam_role.github_actions[0].arn, null)
}
