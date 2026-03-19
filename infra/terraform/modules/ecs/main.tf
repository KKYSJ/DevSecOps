resource "aws_ecs_cluster" "this" {
  name = var.name

  setting {
    name  = "containerInsights"
    value = var.enable_container_insights ? "enabled" : "disabled"
  }

  tags = merge(var.tags, { Name = var.name })
}

resource "aws_service_discovery_private_dns_namespace" "this" {
  count = var.create_service_discovery_namespace ? 1 : 0

  name = var.service_discovery_namespace_name
  vpc  = var.vpc_id

  tags = merge(var.tags, { Name = var.service_discovery_namespace_name })
}
