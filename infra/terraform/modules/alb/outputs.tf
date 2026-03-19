output "arn" {
  description = "ALB ARN."
  value       = aws_lb.this.arn
}

output "dns_name" {
  description = "Public DNS name of the ALB."
  value       = aws_lb.this.dns_name
}

output "zone_id" {
  description = "Hosted zone ID of the ALB."
  value       = aws_lb.this.zone_id
}

output "target_group_arns" {
  description = "Target group ARNs keyed by service name."
  value       = { for name, target_group in aws_lb_target_group.services : name => target_group.arn }
}

output "http_listener_arn" {
  description = "HTTP listener ARN."
  value       = aws_lb_listener.http.arn
}

output "https_listener_arn" {
  description = "HTTPS listener ARN if created."
  value       = try(aws_lb_listener.https[0].arn, null)
}
