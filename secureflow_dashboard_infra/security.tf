data "aws_ec2_managed_prefix_list" "cloudfront_origin_facing" {
  count = var.enable_cloudfront_https ? 1 : 0
  name  = "com.amazonaws.global.cloudfront.origin-facing"
}

resource "aws_security_group" "alb" {
  name        = "${local.name}-alb-sg"
  description = "Public ALB access"
  vpc_id      = aws_vpc.main.id

  dynamic "ingress" {
    for_each = (!var.enable_cloudfront_https || var.acm_certificate_arn == null) ? [1] : []

    content {
      description     = var.enable_cloudfront_https ? "HTTP from CloudFront origins" : "HTTP"
      from_port       = 80
      to_port         = 80
      protocol        = "tcp"
      cidr_blocks     = var.enable_cloudfront_https ? null : ["0.0.0.0/0"]
      prefix_list_ids = var.enable_cloudfront_https ? [try(data.aws_ec2_managed_prefix_list.cloudfront_origin_facing[0].id, null)] : null
    }
  }

  dynamic "ingress" {
    for_each = var.acm_certificate_arn != null ? [1] : []

    content {
      description     = var.enable_cloudfront_https ? "HTTPS from CloudFront origins" : "HTTPS"
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      cidr_blocks     = var.enable_cloudfront_https ? null : ["0.0.0.0/0"]
      prefix_list_ids = var.enable_cloudfront_https ? [try(data.aws_ec2_managed_prefix_list.cloudfront_origin_facing[0].id, null)] : null
    }
  }

  egress {
    description = "ALB to frontend targets"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "ALB to backend targets"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "${local.name}-alb-sg"
  }
}

resource "aws_security_group" "frontend" {
  name        = "${local.name}-frontend-sg"
  description = "Frontend ECS service"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "From ALB to Nginx"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Frontend outbound HTTPS only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name}-frontend-sg"
  }
}

resource "aws_security_group" "backend" {
  name        = "${local.name}-backend-sg"
  description = "Backend ECS service"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "From ALB to API"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Backend outbound HTTPS only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Backend to PostgreSQL"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Backend to Redis TLS"
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "${local.name}-backend-sg"
  }
}

resource "aws_security_group" "rds" {
  name        = "${local.name}-rds-sg"
  description = "PostgreSQL access from backend and worker"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "PostgreSQL from ECS backend"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.backend.id]
  }

  tags = {
    Name = "${local.name}-rds-sg"
  }
}

resource "aws_security_group" "redis" {
  name        = "${local.name}-redis-sg"
  description = "Redis access from backend and worker"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Redis from ECS backend"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.backend.id]
  }

  tags = {
    Name = "${local.name}-redis-sg"
  }
}
