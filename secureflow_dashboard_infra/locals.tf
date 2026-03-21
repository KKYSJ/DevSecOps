locals {
  name = lower(replace("${var.project_name}-${var.environment}", "_", "-"))
  azs  = slice(data.aws_availability_zones.available.names, 0, 2)

  common_tags = merge(
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = var.managed_by
      Service     = "secureflow-dashboard"
    },
    var.tags
  )

  reports_bucket_name = coalesce(
    var.reports_bucket_name,
    lower("${local.name}-${data.aws_caller_identity.current.account_id}-reports")
  )

  db_secret_name = coalesce(
    var.db_secret_name,
    "${local.name}/db"
  )

  redis_secret_name = coalesce(
    var.redis_secret_name,
    "${local.name}/redis"
  )

  external_api_secret_name = coalesce(
    var.external_api_secret_name,
    var.app_secret_name,
    "${local.name}/external-api"
  )

  db_final_snapshot_identifier = "${local.name}-final-${random_id.db_snapshot_suffix.hex}"

  public_subnets = {
    for index, az in local.azs :
    az => cidrsubnet(var.vpc_cidr, 4, index)
  }

  private_app_subnets = {
    for index, az in local.azs :
    az => cidrsubnet(var.vpc_cidr, 4, index + 4)
  }

  private_data_subnets = {
    for index, az in local.azs :
    az => cidrsubnet(var.vpc_cidr, 4, index + 8)
  }

  frontend_image = "${aws_ecr_repository.frontend.repository_url}:${var.frontend_image_tag}"
  backend_image  = "${aws_ecr_repository.backend.repository_url}:${var.backend_image_tag}"
  worker_image   = "${aws_ecr_repository.worker.repository_url}:${var.worker_image_tag}"
}
