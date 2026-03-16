resource "random_string" "suffix" {
  length  = 6
  lower   = true
  upper   = false
  numeric = true
  special = false
}

locals {
  frontend_bucket_name = coalesce(var.frontend_bucket_name, "${var.bucket_prefix}-${var.environment}-frontend-${random_string.suffix.result}")
  uploads_bucket_name  = coalesce(var.uploads_bucket_name, "${var.bucket_prefix}-${var.environment}-uploads-${random_string.suffix.result}")
  cors_allowed_origins = length(var.frontend_cors_allowed_origins) > 0 ? var.frontend_cors_allowed_origins : ["http://localhost:3000"]
}

resource "aws_s3_bucket" "frontend" {
  count = var.create_frontend_bucket ? 1 : 0

  bucket        = local.frontend_bucket_name
  force_destroy = var.force_destroy

  tags = merge(var.tags, { Name = local.frontend_bucket_name })
}

resource "aws_s3_bucket_versioning" "frontend" {
  count = var.create_frontend_bucket ? 1 : 0

  bucket = aws_s3_bucket.frontend[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "frontend" {
  count = var.create_frontend_bucket ? 1 : 0

  bucket = aws_s3_bucket.frontend[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "frontend" {
  count = var.create_frontend_bucket ? 1 : 0

  bucket = aws_s3_bucket.frontend[0].id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = var.kms_key_arn == null ? "AES256" : "aws:kms"
    }
  }
}

resource "aws_s3_bucket" "uploads" {
  count = var.create_uploads_bucket ? 1 : 0

  bucket        = local.uploads_bucket_name
  force_destroy = var.force_destroy

  tags = merge(var.tags, { Name = local.uploads_bucket_name })
}

resource "aws_s3_bucket_versioning" "uploads" {
  count = var.create_uploads_bucket ? 1 : 0

  bucket = aws_s3_bucket.uploads[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  count = var.create_uploads_bucket ? 1 : 0

  bucket = aws_s3_bucket.uploads[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  count = var.create_uploads_bucket ? 1 : 0

  bucket = aws_s3_bucket.uploads[0].id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = var.kms_key_arn == null ? "AES256" : "aws:kms"
    }
  }
}

resource "aws_s3_bucket_cors_configuration" "uploads" {
  count = var.create_uploads_bucket ? 1 : 0

  bucket = aws_s3_bucket.uploads[0].id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "PUT", "POST"]
    allowed_origins = local.cors_allowed_origins
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}
