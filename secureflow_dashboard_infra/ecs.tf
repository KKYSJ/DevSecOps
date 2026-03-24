resource "aws_ecs_cluster" "main" {
  name = "${local.name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_lb" "main" {
  name                       = substr("${local.name}-alb", 0, 32)
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = [for subnet in aws_subnet.public : subnet.id]
  enable_deletion_protection = var.environment == "prod"
  desync_mitigation_mode     = "strictest"
  drop_invalid_header_fields = true
  enable_http2               = true

  access_logs {
    bucket  = aws_s3_bucket.logs.id
    prefix  = "alb"
    enabled = true
  }
}

resource "aws_lb_target_group" "frontend" {
  name        = substr("${local.name}-fe-tg", 0, 32)
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    enabled             = true
    path                = "/health"
    matcher             = "200-399"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_target_group" "backend" {
  name        = substr("${local.name}-be-tg", 0, 32)
  port        = 8000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    enabled             = true
    path                = "/health"
    matcher             = "200-399"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http_forward" {
  count = var.acm_certificate_arn == null ? 1 : 0

  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.frontend.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  count = var.acm_certificate_arn != null ? 1 : 0

  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      protocol    = "HTTPS"
      port        = "443"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  count = var.acm_certificate_arn != null ? 1 : 0

  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.frontend.arn
  }
}

resource "aws_lb_listener_rule" "api_http" {
  count = var.acm_certificate_arn == null ? 1 : 0

  listener_arn = aws_lb_listener.http_forward[0].arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend.arn
  }

  condition {
    path_pattern {
      values = ["/api/*", "/docs*", "/redoc*", "/openapi.json", "/health"]
    }
  }
}

resource "aws_lb_listener_rule" "api_https" {
  count = var.acm_certificate_arn != null ? 1 : 0

  listener_arn = aws_lb_listener.https[0].arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend.arn
  }

  condition {
    path_pattern {
      values = ["/api/*", "/docs*", "/redoc*", "/openapi.json", "/health"]
    }
  }
}

resource "aws_ecs_task_definition" "frontend" {
  family                   = "${local.name}-frontend"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.frontend_cpu)
  memory                   = tostring(var.frontend_memory)
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.frontend_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "nginx-tmp"
  }

  container_definitions = jsonencode([
    {
      name      = "frontend"
      image     = local.frontend_image
      essential = true
      entryPoint = [
        "/bin/sh",
        "-c"
      ]
      command = [
        "mkdir -p /tmp/nginx/client_temp /tmp/nginx/proxy_temp /tmp/nginx/fastcgi_temp /tmp/nginx/uwsgi_temp /tmp/nginx/scgi_temp && exec nginx -g 'daemon off;'"
      ]
      portMappings = [
        {
          containerPort = 80
          hostPort      = 80
          protocol      = "tcp"
        }
      ]
      readonlyRootFilesystem = true
      mountPoints = [
        {
          sourceVolume  = "nginx-tmp"
          containerPath = "/tmp"
          readOnly      = false
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.frontend.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_task_definition" "backend" {
  family                   = "${local.name}-backend"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.backend_cpu)
  memory                   = tostring(var.backend_memory)
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.backend_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "backend-tmp"
  }

  container_definitions = jsonencode([
    {
      name      = "backend"
      image     = local.backend_image
      essential = true
      command   = ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
      portMappings = [
        {
          containerPort = 8000
          hostPort      = 8000
          protocol      = "tcp"
        }
      ]
      readonlyRootFilesystem = true
      mountPoints = [
        {
          sourceVolume  = "backend-tmp"
          containerPath = "/tmp"
          readOnly      = false
        }
      ]
      environment = [
        { name = "APP_ENV", value = var.environment },
        { name = "AWS_REGION", value = var.aws_region },
        { name = "AWS_ACCOUNT_ID", value = data.aws_caller_identity.current.account_id },
        { name = "S3_REPORT_BUCKET", value = aws_s3_bucket.reports.id },
        { name = "GEMINI_MODEL", value = var.gemini_model },
        { name = "SONAR_HOST_URL", value = var.sonar_host_url },
        { name = "SONARQUBE_URL", value = var.sonar_host_url },
        { name = "SONAR_ORGANIZATION", value = var.sonar_organization },
        { name = "SONAR_PROJECT_KEY", value = var.sonar_project_key }
      ]
      secrets = [
        { name = "DATABASE_URL", valueFrom = "${aws_secretsmanager_secret.db.arn}:DATABASE_URL::" },
        { name = "REDIS_URL", valueFrom = "${aws_secretsmanager_secret.redis.arn}:REDIS_URL::" },
        { name = "CELERY_BROKER_URL", valueFrom = "${aws_secretsmanager_secret.redis.arn}:CELERY_BROKER_URL::" },
        { name = "CELERY_RESULT_BACKEND", valueFrom = "${aws_secretsmanager_secret.redis.arn}:CELERY_RESULT_BACKEND::" },
        { name = "GEMINI_API_KEY", valueFrom = "${aws_secretsmanager_secret.external_api.arn}:GEMINI_API_KEY::" },
        { name = "OPENAI_API_KEY", valueFrom = "${aws_secretsmanager_secret.external_api.arn}:OPENAI_API_KEY::" },
        { name = "SONAR_TOKEN", valueFrom = "${aws_secretsmanager_secret.external_api.arn}:SONAR_TOKEN::" },
        { name = "SONARQUBE_TOKEN", valueFrom = "${aws_secretsmanager_secret.external_api.arn}:SONAR_TOKEN::" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.backend.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "${local.name}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.worker_cpu)
  memory                   = tostring(var.worker_memory)
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.backend_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "worker-tmp"
  }

  container_definitions = jsonencode([
    {
      name                   = "worker"
      image                  = local.worker_image
      essential              = true
      command                = ["celery", "-A", "backend.app.core.celery_app.celery_app", "worker", "--loglevel=info"]
      readonlyRootFilesystem = true
      mountPoints = [
        {
          sourceVolume  = "worker-tmp"
          containerPath = "/tmp"
          readOnly      = false
        }
      ]
      environment = [
        { name = "APP_ENV", value = var.environment },
        { name = "AWS_REGION", value = var.aws_region },
        { name = "AWS_ACCOUNT_ID", value = data.aws_caller_identity.current.account_id },
        { name = "S3_REPORT_BUCKET", value = aws_s3_bucket.reports.id },
        { name = "GEMINI_MODEL", value = var.gemini_model },
        { name = "SONAR_HOST_URL", value = var.sonar_host_url },
        { name = "SONARQUBE_URL", value = var.sonar_host_url },
        { name = "SONAR_ORGANIZATION", value = var.sonar_organization },
        { name = "SONAR_PROJECT_KEY", value = var.sonar_project_key },
        { name = "PYTHONPATH", value = "/app" }
      ]
      secrets = [
        { name = "DATABASE_URL", valueFrom = "${aws_secretsmanager_secret.db.arn}:DATABASE_URL::" },
        { name = "REDIS_URL", valueFrom = "${aws_secretsmanager_secret.redis.arn}:REDIS_URL::" },
        { name = "CELERY_BROKER_URL", valueFrom = "${aws_secretsmanager_secret.redis.arn}:CELERY_BROKER_URL::" },
        { name = "CELERY_RESULT_BACKEND", valueFrom = "${aws_secretsmanager_secret.redis.arn}:CELERY_RESULT_BACKEND::" },
        { name = "GEMINI_API_KEY", valueFrom = "${aws_secretsmanager_secret.external_api.arn}:GEMINI_API_KEY::" },
        { name = "OPENAI_API_KEY", valueFrom = "${aws_secretsmanager_secret.external_api.arn}:OPENAI_API_KEY::" },
        { name = "SONAR_TOKEN", valueFrom = "${aws_secretsmanager_secret.external_api.arn}:SONAR_TOKEN::" },
        { name = "SONARQUBE_TOKEN", valueFrom = "${aws_secretsmanager_secret.external_api.arn}:SONAR_TOKEN::" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.worker.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "frontend" {
  name                               = "${local.name}-frontend"
  cluster                            = aws_ecs_cluster.main.id
  task_definition                    = aws_ecs_task_definition.frontend.arn
  desired_count                      = var.frontend_desired_count
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  launch_type                        = "FARGATE"
  health_check_grace_period_seconds  = 60
  enable_execute_command             = true
  wait_for_steady_state              = true

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    assign_public_ip = false
    subnets          = [for subnet in aws_subnet.private_app : subnet.id]
    security_groups  = [aws_security_group.frontend.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.frontend.arn
    container_name   = "frontend"
    container_port   = 80
  }

  depends_on = [
    aws_lb_listener.http_forward,
    aws_lb_listener.http_redirect,
    aws_lb_listener.https
  ]
}

resource "aws_ecs_service" "backend" {
  name                               = "${local.name}-backend"
  cluster                            = aws_ecs_cluster.main.id
  task_definition                    = aws_ecs_task_definition.backend.arn
  desired_count                      = var.backend_desired_count
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  launch_type                        = "FARGATE"
  health_check_grace_period_seconds  = 60
  enable_execute_command             = true
  wait_for_steady_state              = true

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    assign_public_ip = false
    subnets          = [for subnet in aws_subnet.private_app : subnet.id]
    security_groups  = [aws_security_group.backend.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.backend.arn
    container_name   = "backend"
    container_port   = 8000
  }

  depends_on = [
    aws_lb_listener_rule.api_http,
    aws_lb_listener_rule.api_https
  ]
}

resource "aws_ecs_service" "worker" {
  name                               = "${local.name}-worker"
  cluster                            = aws_ecs_cluster.main.id
  task_definition                    = aws_ecs_task_definition.worker.arn
  desired_count                      = var.worker_desired_count
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  launch_type                        = "FARGATE"
  enable_execute_command             = true
  wait_for_steady_state              = true

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    assign_public_ip = false
    subnets          = [for subnet in aws_subnet.private_app : subnet.id]
    security_groups  = [aws_security_group.backend.id]
  }
}

resource "aws_appautoscaling_target" "frontend" {
  count = var.enable_autoscaling ? 1 : 0

  max_capacity       = var.frontend_max_capacity
  min_capacity       = var.frontend_min_capacity
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.frontend.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_target" "backend" {
  count = var.enable_autoscaling ? 1 : 0

  max_capacity       = var.backend_max_capacity
  min_capacity       = var.backend_min_capacity
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.backend.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "frontend_cpu" {
  count = var.enable_autoscaling ? 1 : 0

  name               = "${local.name}-frontend-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.frontend[0].resource_id
  scalable_dimension = aws_appautoscaling_target.frontend[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.frontend[0].service_namespace

  target_tracking_scaling_policy_configuration {
    target_value = var.cpu_scale_target

    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}

resource "aws_appautoscaling_policy" "backend_cpu" {
  count = var.enable_autoscaling ? 1 : 0

  name               = "${local.name}-backend-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.backend[0].resource_id
  scalable_dimension = aws_appautoscaling_target.backend[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.backend[0].service_namespace

  target_tracking_scaling_policy_configuration {
    target_value = var.cpu_scale_target

    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}
