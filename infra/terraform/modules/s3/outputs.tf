output "frontend_bucket_name" {
  description = "Name of the static frontend bucket."
  value       = try(aws_s3_bucket.frontend[0].bucket, null)
}

output "frontend_bucket_arn" {
  description = "ARN of the static frontend bucket."
  value       = try(aws_s3_bucket.frontend[0].arn, null)
}

output "uploads_bucket_name" {
  description = "Name of the uploads bucket."
  value       = try(aws_s3_bucket.uploads[0].bucket, null)
}

output "uploads_bucket_arn" {
  description = "ARN of the uploads bucket."
  value       = try(aws_s3_bucket.uploads[0].arn, null)
}
