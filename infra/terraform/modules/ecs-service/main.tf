locals {
  environment = [
    for key, value in var.environment_variables : {
      name  = key
      value = value
    }
  ]

  secrets = [
    for key, value in var.secret_environment_variables : {
      name      = key
      valueFrom = value
    }
  ]
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.service_name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.cpu)
  memory                   = tostring(var.memory)
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn

  container_definitions = jsonencode([
    {
      name      = var.container_name
      image     = var.container_image
      essential = true

      portMappings = [
        {
          containerPort = var.container_port
          hostPort      = var.container_port
          protocol      = "tcp"
        }
      ]

      environment = local.environment
      secrets     = local.secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = var.log_group_name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = var.container_name
        }
      }
    }
  ])

  tags = merge(var.tags, { Name = var.service_name })
}

resource "aws_ecs_service" "this" {
  name                               = var.service_name
  cluster                            = var.cluster_arn
  task_definition                    = aws_ecs_task_definition.this.arn
  desired_count                      = var.desired_count
  launch_type                        = "FARGATE"
  health_check_grace_period_seconds  = var.health_check_grace_period_seconds
  enable_execute_command             = true
  wait_for_steady_state              = false

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = var.security_group_ids
    assign_public_ip = var.assign_public_ip
  }

  load_balancer {
    target_group_arn = var.target_group_arn
    container_name   = var.container_name
    container_port   = var.container_port
  }

  tags = merge(var.tags, { Name = var.service_name })
}
