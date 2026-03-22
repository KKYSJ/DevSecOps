resource "aws_s3_bucket" "security_logs" {
  count = var.create_security_logs_bucket ? 1 : 0

  bucket        = "${local.name_prefix}-${data.aws_caller_identity.current.account_id}-security-logs"
  force_destroy = var.security_logs_bucket_force_destroy

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-security-logs" })
}

resource "aws_s3_bucket_versioning" "security_logs" {
  count = var.create_security_logs_bucket ? 1 : 0

  bucket = aws_s3_bucket.security_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "security_logs" {
  count = var.create_security_logs_bucket ? 1 : 0

  bucket = aws_s3_bucket.security_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_logs" {
  count = var.create_security_logs_bucket ? 1 : 0

  bucket = aws_s3_bucket.security_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "security_logs" {
  count = var.create_security_logs_bucket ? 1 : 0

  bucket = aws_s3_bucket.security_logs[0].id

  rule {
    id     = "cleanup-incomplete-multipart-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "security_logs" {
  count = var.create_security_logs_bucket ? 1 : 0

  statement {
    sid = "AWSConfigBucketPermissionsCheck"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.security_logs[0].arn]
  }

  statement {
    sid = "AWSConfigBucketDelivery"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.security_logs[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid = "CloudTrailAclCheck"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.security_logs[0].arn]
  }

  statement {
    sid = "CloudTrailWrite"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.security_logs[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "security_logs" {
  count = var.create_security_logs_bucket ? 1 : 0

  bucket = aws_s3_bucket.security_logs[0].id
  policy = data.aws_iam_policy_document.security_logs[0].json
}
