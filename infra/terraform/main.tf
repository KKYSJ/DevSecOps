data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  availability_zones = length(var.availability_zones) > 0 ? var.availability_zones : slice(data.aws_availability_zones.available.names, 0, 2)
  name_prefix        = "${var.project_name}-${var.environment}"

  common_tags = merge(
    var.default_tags,
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  )

  api_services = {
    api-server-node = {
      port              = 5000
      health_check_path = "/api/health"
    }
    api-server-fastapi = {
      port              = 8000
      health_check_path = "/api/health"
    }
    api-server-spring = {
      port              = 8080
      health_check_path = "/api/health"
    }
  }

  workload_names = concat(keys(local.api_services), ["frontend"])

  ecr_repositories = {
    for name in local.workload_names : name => {
      image_tag_mutability = "IMMUTABLE"
      scan_on_push         = true
      lifecycle_max_images = 30
    }
  }

  fastapi_image_uri = "${module.ecr.repository_urls["api-server-fastapi"]}:${var.fastapi_image_tag}"

  fastapi_environment = merge(
    {
      PORT            = "8000"
      DB_TYPE         = "sqlite"
      STORAGE_TYPE    = "s3"
      S3_BUCKET       = module.s3.uploads_bucket_name
      S3_REGION       = var.aws_region
      REVIEW_STORE    = "dynamodb"
      DYNAMODB_TABLE  = aws_dynamodb_table.reviews.name
      DYNAMODB_REGION = var.aws_region
      CACHE_TYPE      = "memory"
      QUEUE_TYPE      = "sqs"
      SQS_QUEUE_URL   = aws_sqs_queue.orders.url
      SNS_TOPIC_ARN   = aws_sns_topic.orders.arn
    },
    var.fastapi_environment_overrides
  )
}

module "vpc" {
  source = "./modules/vpc"

  name                     = local.name_prefix
  vpc_cidr                 = var.vpc_cidr
  availability_zones       = local.availability_zones
  public_subnet_cidrs      = var.public_subnet_cidrs
  private_app_subnet_cidrs = var.private_app_subnet_cidrs
  private_data_subnet_cidrs = var.private_data_subnet_cidrs
  single_nat_gateway       = var.single_nat_gateway
  allowed_ingress_cidrs    = var.allowed_ingress_cidrs
  app_ingress_ports        = [for service in values(local.api_services) : service.port]
  tags                     = local.common_tags
}

module "ecr" {
  source = "./modules/ecr"

  repositories = local.ecr_repositories
  tags         = local.common_tags
}

module "s3" {
  source = "./modules/s3"

  bucket_prefix             = var.project_name
  environment               = var.environment
  frontend_bucket_name      = var.frontend_bucket_name
  uploads_bucket_name       = var.uploads_bucket_name
  frontend_cors_allowed_origins = var.frontend_allowed_origins
  tags                      = local.common_tags
}

resource "aws_dynamodb_table" "reviews" {
  name         = coalesce(var.reviews_table_name, "${local.name_prefix}-reviews")
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "productId"
  range_key    = "reviewId"

  attribute {
    name = "productId"
    type = var.review_table_hash_key_type
  }

  attribute {
    name = "reviewId"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-reviews" })
}

resource "aws_sqs_queue" "orders" {
  name                      = coalesce(var.orders_queue_name, "${local.name_prefix}-orders")
  message_retention_seconds = 345600
  visibility_timeout_seconds = 60
  sqs_managed_sse_enabled   = true

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-orders" })
}

resource "aws_sns_topic" "orders" {
  name = coalesce(var.orders_topic_name, "${local.name_prefix}-orders")

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-orders" })
}

module "ecs" {
  source = "./modules/ecs"

  name                           = "${local.name_prefix}-cluster"
  vpc_id                         = module.vpc.vpc_id
  service_discovery_namespace_name = "${var.environment}.${var.project_name}.local"
  tags                           = local.common_tags
}

module "alb" {
  source = "./modules/alb"

  name                 = "${local.name_prefix}-alb"
  vpc_id               = module.vpc.vpc_id
  public_subnet_ids    = module.vpc.public_subnet_ids
  security_group_ids   = [module.vpc.alb_security_group_id]
  service_target_groups = local.api_services
  certificate_arn      = var.acm_certificate_arn
  tags                 = local.common_tags
}

module "monitoring" {
  source = "./modules/monitoring"

  project_name          = var.project_name
  environment           = var.environment
  service_names         = local.workload_names
  log_retention_in_days = var.log_retention_in_days
  tags                  = local.common_tags
}

module "rds" {
  count  = var.create_rds ? 1 : 0
  source = "./modules/rds"

  identifier               = "${local.name_prefix}-mysql"
  db_name                  = var.db_name
  username                 = var.db_username
  instance_class           = var.db_instance_class
  allocated_storage        = var.db_allocated_storage
  engine_version           = var.db_engine_version
  subnet_ids               = module.vpc.private_data_subnet_ids
  vpc_security_group_ids   = [module.vpc.rds_security_group_id]
  multi_az                 = var.db_multi_az
  backup_retention_period  = var.db_backup_retention_period
  deletion_protection      = var.db_deletion_protection
  skip_final_snapshot      = var.db_skip_final_snapshot
  tags                     = local.common_tags
}

module "iam_kms" {
  source = "./modules/iam-kms"

  project_name            = var.project_name
  environment             = var.environment
  create_github_oidc_role = var.create_github_oidc_role
  github_org              = var.github_org
  github_repo             = var.github_repo
  github_branch           = var.github_branch
  github_oidc_subjects    = var.github_oidc_subjects
  github_oidc_thumbprints = var.github_oidc_thumbprints
  ecr_repository_arns     = values(module.ecr.repository_arns)
  frontend_bucket_arn     = module.s3.frontend_bucket_arn
  uploads_bucket_arn      = module.s3.uploads_bucket_arn
  dynamodb_table_arn      = aws_dynamodb_table.reviews.arn
  sqs_queue_arn           = aws_sqs_queue.orders.arn
  sns_topic_arn           = aws_sns_topic.orders.arn
  tags                    = local.common_tags
}

resource "random_password" "fastapi_jwt_secret" {
  count   = var.enable_fastapi_service ? 1 : 0
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "fastapi_jwt" {
  count = var.enable_fastapi_service ? 1 : 0

  name                    = coalesce(var.fastapi_jwt_secret_name, "${local.name_prefix}-fastapi-jwt")
  recovery_window_in_days = 0

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-fastapi-jwt" })
}

resource "aws_secretsmanager_secret_version" "fastapi_jwt" {
  count = var.enable_fastapi_service ? 1 : 0

  secret_id     = aws_secretsmanager_secret.fastapi_jwt[0].id
  secret_string = random_password.fastapi_jwt_secret[0].result
}

module "fastapi_service" {
  count  = var.enable_fastapi_service ? 1 : 0
  source = "./modules/ecs-service"

  service_name                  = "${local.name_prefix}-api-server-fastapi"
  cluster_arn                   = module.ecs.cluster_arn
  subnet_ids                    = module.vpc.private_app_subnet_ids
  security_group_ids            = [module.vpc.ecs_security_group_id]
  target_group_arn              = module.alb.target_group_arns["api-server-fastapi"]
  container_name                = "api-server-fastapi"
  container_image               = local.fastapi_image_uri
  container_port                = 8000
  cpu                           = var.fastapi_cpu
  memory                        = var.fastapi_memory
  desired_count                 = var.fastapi_desired_count
  assign_public_ip              = var.fastapi_assign_public_ip
  execution_role_arn            = module.iam_kms.ecs_execution_role_arn
  task_role_arn                 = module.iam_kms.ecs_task_role_arn
  log_group_name                = module.monitoring.log_group_names["api-server-fastapi"]
  aws_region                    = var.aws_region
  environment_variables         = local.fastapi_environment
  secret_environment_variables  = { JWT_SECRET = aws_secretsmanager_secret.fastapi_jwt[0].arn }
  tags                          = local.common_tags
}

resource "aws_lb_listener_rule" "fastapi_http" {
  count = var.enable_fastapi_service ? 1 : 0

  listener_arn = module.alb.http_listener_arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = module.alb.target_group_arns["api-server-fastapi"]
  }

  condition {
    path_pattern {
      values = var.fastapi_path_patterns
    }
  }
}

resource "aws_lb_listener_rule" "fastapi_https" {
  count = var.enable_fastapi_service && var.acm_certificate_arn != null ? 1 : 0

  listener_arn = module.alb.https_listener_arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = module.alb.target_group_arns["api-server-fastapi"]
  }

  condition {
    path_pattern {
      values = var.fastapi_path_patterns
    }
  }
}
