output "security_logs_bucket_name" {
  description = "Bucket used for security service log delivery."
  value       = local.security_logs_bucket_name
}

output "cloudtrail_arn" {
  description = "CloudTrail ARN when managed by this stack."
  value       = try(aws_cloudtrail.main[0].arn, null)
}

output "config_recorder_name" {
  description = "AWS Config recorder name when managed by this stack."
  value       = try(aws_config_configuration_recorder.main[0].name, null)
}

output "securityhub_account_id" {
  description = "Security Hub account ID when managed by this stack."
  value       = try(aws_securityhub_account.main[0].id, null)
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID when managed by this stack."
  value       = try(aws_guardduty_detector.main[0].id, null)
}

output "flow_log_ids" {
  description = "Managed VPC Flow Log IDs."
  value       = { for vpc_id, flow_log in aws_flow_log.vpc : vpc_id => flow_log.id }
}

output "incident_response_plan_arn" {
  description = "Incident response plan ARN when managed by this stack."
  value       = try(aws_ssmincidents_response_plan.basic[0].arn, null)
}
