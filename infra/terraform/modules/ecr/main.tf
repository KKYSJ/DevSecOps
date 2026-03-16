locals {
  normalized_repositories = {
    for name, repository in var.repositories : name => merge(
      {
        image_tag_mutability = "IMMUTABLE"
        scan_on_push         = true
        lifecycle_max_images = 30
      },
      repository
    )
  }
}

resource "aws_ecr_repository" "this" {
  for_each = local.normalized_repositories

  name                 = each.key
  image_tag_mutability = each.value.image_tag_mutability
  force_delete         = var.force_delete

  image_scanning_configuration {
    scan_on_push = each.value.scan_on_push
  }

  encryption_configuration {
    encryption_type = var.kms_key_arn == null ? "AES256" : "KMS"
    kms_key         = var.kms_key_arn
  }

  tags = merge(var.tags, { Name = each.key })
}

resource "aws_ecr_lifecycle_policy" "this" {
  for_each = local.normalized_repositories

  repository = aws_ecr_repository.this[each.key].name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep only the latest tagged images"
        selection = {
          tagStatus   = "tagged"
          tagPrefixList = ["v", "main", "dev", "prod"]
          countType   = "imageCountMoreThan"
          countNumber = each.value.lifecycle_max_images
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Expire untagged images after the same retention window"
        selection = {
          tagStatus   = "untagged"
          countType   = "imageCountMoreThan"
          countNumber = each.value.lifecycle_max_images
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}
