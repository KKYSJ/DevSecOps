output "log_group_names" {
  description = "CloudWatch log group names keyed by service."
  value       = { for name, log_group in aws_cloudwatch_log_group.services : name => log_group.name }
}

output "log_group_arns" {
  description = "CloudWatch log group ARNs keyed by service."
  value       = { for name, log_group in aws_cloudwatch_log_group.services : name => log_group.arn }
}

output "alerts_topic_arn" {
  description = "SNS topic ARN for infrastructure alerts when created."
  value       = try(aws_sns_topic.alerts[0].arn, null)
}
