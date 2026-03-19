output "repository_names" {
  description = "Names of the created ECR repositories."
  value       = { for name, repository in aws_ecr_repository.this : name => repository.name }
}

output "repository_urls" {
  description = "Repository URLs keyed by logical service name."
  value       = { for name, repository in aws_ecr_repository.this : name => repository.repository_url }
}

output "repository_arns" {
  description = "Repository ARNs keyed by logical service name."
  value       = { for name, repository in aws_ecr_repository.this : name => repository.arn }
}
