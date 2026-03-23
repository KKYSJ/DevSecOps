locals {
  name_prefix = "${var.project_name}-${var.environment}"

  github_subjects = length(var.github_oidc_subjects) > 0 ? var.github_oidc_subjects : (
    var.github_org != "" && var.github_repo != "" ? ["repo:${var.github_org}/${var.github_repo}:ref:refs/heads/${var.github_branch}"] : []
  )

  deployment_bucket_arns = compact([var.frontend_bucket_arn, var.uploads_bucket_arn])
  deployment_object_arns = [for arn in local.deployment_bucket_arns : "${arn}/*"]
  github_oidc_provider_arn = var.create_github_oidc_role ? (
    var.create_github_oidc_provider
    ? aws_iam_openid_connect_provider.github[0].arn
    : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
  ) : null
}

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "this" {
  description             = "Application KMS key for ${local.name_prefix}"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = merge(var.tags, { Name = "${local.name_prefix}-kms" })
}

resource "aws_kms_alias" "this" {
  name          = "alias/${local.name_prefix}"
  target_key_id = aws_kms_key.this.key_id
}

data "aws_iam_policy_document" "ecs_task_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_execution" {
  name               = "${local.name_prefix}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume_role.json

  tags = merge(var.tags, { Name = "${local.name_prefix}-ecs-execution" })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_managed" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "ecs_execution_extra" {
  statement {
    actions = [
      "kms:Decrypt",
      "secretsmanager:GetSecretValue",
      "ssm:GetParameter",
      "ssm:GetParameters"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "ecs_execution_extra" {
  name   = "${local.name_prefix}-ecs-execution-extra"
  role   = aws_iam_role.ecs_execution.id
  policy = data.aws_iam_policy_document.ecs_execution_extra.json
}

resource "aws_iam_role" "ecs_task" {
  name               = "${local.name_prefix}-ecs-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume_role.json

  tags = merge(var.tags, { Name = "${local.name_prefix}-ecs-task" })
}

data "aws_iam_policy_document" "ecs_task_permissions" {
  dynamic "statement" {
    for_each = var.uploads_bucket_arn == null ? [] : [1]

    content {
      sid       = "UploadsBucketList"
      actions   = ["s3:ListBucket"]
      resources = [var.uploads_bucket_arn]
    }
  }

  dynamic "statement" {
    for_each = var.uploads_bucket_arn == null ? [] : [1]

    content {
      sid = "UploadsBucketObjects"
      actions = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ]
      resources = ["${var.uploads_bucket_arn}/*"]
    }
  }

  dynamic "statement" {
    for_each = var.dynamodb_table_arn == null ? [] : [1]

    content {
      sid = "ReviewsTableAccess"
      actions = [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:Query",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem"
      ]
      resources = [var.dynamodb_table_arn]
    }
  }

  dynamic "statement" {
    for_each = var.sqs_queue_arn == null ? [] : [1]

    content {
      sid = "OrdersQueueAccess"
      actions = [
        "sqs:GetQueueAttributes",
        "sqs:GetQueueUrl",
        "sqs:SendMessage"
      ]
      resources = [var.sqs_queue_arn]
    }
  }

  dynamic "statement" {
    for_each = var.sns_topic_arn == null ? [] : [1]

    content {
      sid       = "OrdersTopicPublish"
      actions   = ["sns:Publish"]
      resources = [var.sns_topic_arn]
    }
  }
}

resource "aws_iam_role_policy" "ecs_task_permissions" {
  name   = "${local.name_prefix}-ecs-task-permissions"
  role   = aws_iam_role.ecs_task.id
  policy = data.aws_iam_policy_document.ecs_task_permissions.json
}

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_role && var.create_github_oidc_provider ? 1 : 0

  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = var.github_oidc_thumbprints
}

data "aws_iam_policy_document" "github_actions_assume_role" {
  count = var.create_github_oidc_role ? 1 : 0

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = local.github_subjects
    }
  }
}

resource "aws_iam_role" "github_actions" {
  count = var.create_github_oidc_role ? 1 : 0

  name               = "${local.name_prefix}-github-actions"
  assume_role_policy = data.aws_iam_policy_document.github_actions_assume_role[0].json

  lifecycle {
    precondition {
      condition     = length(local.github_subjects) > 0
      error_message = "Set github_org/github_repo or github_oidc_subjects when create_github_oidc_role is true."
    }
  }

  tags = merge(var.tags, { Name = "${local.name_prefix}-github-actions" })
}

data "aws_iam_policy_document" "github_actions_permissions" {
  count = var.create_github_oidc_role ? 1 : 0

  statement {
    sid       = "EcrAuthorization"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = length(var.ecr_repository_arns) == 0 ? [] : [1]

    content {
      sid = "EcrPushPull"
      actions = [
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:CompleteLayerUpload",
        "ecr:DescribeImages",
        "ecr:DescribeRepositories",
        "ecr:GetDownloadUrlForLayer",
        "ecr:InitiateLayerUpload",
        "ecr:ListImages",
        "ecr:PutImage",
        "ecr:UploadLayerPart"
      ]
      resources = var.ecr_repository_arns
    }
  }

  dynamic "statement" {
    for_each = length(local.deployment_bucket_arns) == 0 ? [] : [1]

    content {
      sid       = "DeploymentBucketList"
      actions   = ["s3:ListBucket"]
      resources = local.deployment_bucket_arns
    }
  }

  dynamic "statement" {
    for_each = length(local.deployment_object_arns) == 0 ? [] : [1]

    content {
      sid = "DeploymentBucketObjects"
      actions = [
        "s3:DeleteObject",
        "s3:GetObject",
        "s3:PutObject"
      ]
      resources = local.deployment_object_arns
    }
  }

  statement {
    sid = "EcsDeploy"
    actions = [
      "ecs:DescribeClusters",
      "ecs:DescribeServices",
      "ecs:DescribeTaskDefinition",
      "ecs:ListServices",
      "ecs:ListTasks",
      "ecs:RegisterTaskDefinition",
      "ecs:TagResource",
      "ecs:UpdateService"
    ]
    resources = ["*"]
  }

  statement {
    sid = "DescribeLoadBalancing"
    actions = [
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTargetGroups"
    ]
    resources = ["*"]
  }

  statement {
    sid     = "PassEcsRoles"
    actions = ["iam:PassRole"]
    resources = [
      aws_iam_role.ecs_execution.arn,
      aws_iam_role.ecs_task.arn
    ]
  }
}

resource "aws_iam_policy" "github_actions" {
  count = var.create_github_oidc_role ? 1 : 0

  name   = "${local.name_prefix}-github-actions"
  policy = data.aws_iam_policy_document.github_actions_permissions[0].json

  tags = merge(var.tags, { Name = "${local.name_prefix}-github-actions" })
}

resource "aws_iam_role_policy_attachment" "github_actions" {
  count = var.create_github_oidc_role ? 1 : 0

  role       = aws_iam_role.github_actions[0].name
  policy_arn = aws_iam_policy.github_actions[0].arn
}
