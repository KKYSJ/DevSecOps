data "aws_iam_policy_document" "ecs_tasks_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "ecs_task_execution" {
  name               = "${local.name}-ecs-task-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_default" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "ecs_execution_secrets" {
  statement {
    sid    = "ReadRuntimeSecrets"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue"
    ]
    resources = [
      aws_secretsmanager_secret.db.arn,
      aws_secretsmanager_secret.redis.arn,
      aws_secretsmanager_secret.external_api.arn
    ]
  }

  statement {
    sid    = "DecryptAppSecret"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey"
    ]
    resources = [aws_kms_key.app.arn]
  }
}

resource "aws_iam_role_policy" "ecs_execution_secrets" {
  name   = "${local.name}-ecs-execution-secrets"
  role   = aws_iam_role.ecs_task_execution.id
  policy = data.aws_iam_policy_document.ecs_execution_secrets.json
}

resource "aws_iam_role" "frontend_task" {
  name               = "${local.name}-frontend-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume_role.json
}

resource "aws_iam_role" "backend_task" {
  name               = "${local.name}-backend-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume_role.json
}

data "aws_iam_policy_document" "backend_task" {
  statement {
    sid    = "ReportsBucketAccess"
    effect = "Allow"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:PutObject"
    ]
    resources = [
      aws_s3_bucket.reports.arn,
      "${aws_s3_bucket.reports.arn}/*"
    ]
  }

  statement {
    sid    = "ReportsBucketKms"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey"
    ]
    resources = [aws_kms_key.app.arn]
  }
}

resource "aws_iam_role_policy" "backend_task" {
  name   = "${local.name}-backend-task"
  role   = aws_iam_role.backend_task.id
  policy = data.aws_iam_policy_document.backend_task.json

  depends_on = [aws_iam_role_policy_attachment.backend_task_ismsp_readonly]
}

resource "aws_iam_role_policy_attachment" "backend_task_ismsp_readonly" {
  role       = aws_iam_role.backend_task.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:policy/ISMSP-ReadOnly-Policy"
}

data "aws_iam_policy_document" "rds_enhanced_monitoring_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "rds_enhanced_monitoring" {
  name               = "${local.name}-rds-monitoring"
  assume_role_policy = data.aws_iam_policy_document.rds_enhanced_monitoring_assume_role.json
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  role       = aws_iam_role.rds_enhanced_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

data "aws_iam_policy_document" "vpc_flow_logs_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "vpc_flow_logs" {
  name               = "${local.name}-vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.vpc_flow_logs_assume_role.json
}

data "aws_iam_policy_document" "vpc_flow_logs" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams"
    ]
    resources = [
      aws_cloudwatch_log_group.vpc_flow_logs.arn,
      "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
    ]
  }
}

resource "aws_iam_role_policy" "vpc_flow_logs" {
  name   = "${local.name}-vpc-flow-logs"
  role   = aws_iam_role.vpc_flow_logs.id
  policy = data.aws_iam_policy_document.vpc_flow_logs.json
}
