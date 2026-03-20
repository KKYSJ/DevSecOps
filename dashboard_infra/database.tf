resource "random_password" "db_password" {
  length  = 24
  special = false
}

resource "random_id" "db_snapshot_suffix" {
  byte_length = 4
}

resource "aws_db_subnet_group" "main" {
  name       = "${local.name}-db-subnets"
  subnet_ids = [for subnet in aws_subnet.private_data : subnet.id]
}

resource "aws_db_parameter_group" "postgres" {
  name        = "${local.name}-postgres16"
  family      = "postgres16"
  description = "SecureFlow PostgreSQL parameter group"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_db_instance" "postgres" {
  identifier                      = "${local.name}-postgres"
  engine                          = "postgres"
  engine_version                  = var.db_engine_version
  instance_class                  = var.db_instance_class
  allocated_storage               = var.db_allocated_storage
  max_allocated_storage           = var.db_max_allocated_storage
  storage_type                    = "gp3"
  storage_encrypted               = true
  db_name                         = var.db_name
  username                        = var.db_username
  password                        = random_password.db_password.result
  port                            = 5432
  db_subnet_group_name            = aws_db_subnet_group.main.name
  vpc_security_group_ids          = [aws_security_group.rds.id]
  parameter_group_name            = aws_db_parameter_group.postgres.name
  backup_retention_period         = var.db_backup_retention_period
  maintenance_window              = "Sun:16:00-Sun:17:00"
  backup_window                   = "17:00-18:00"
  multi_az                        = var.db_multi_az
  publicly_accessible             = false
  deletion_protection             = var.environment == "prod"
  skip_final_snapshot             = true
  final_snapshot_identifier       = var.environment == "prod" ? local.db_final_snapshot_identifier : null
  auto_minor_version_upgrade      = true
  copy_tags_to_snapshot           = true
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.app.arn

  # 운영 최소 권장값: PostgreSQL 로그 내보내기 + Enhanced Monitoring.
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  monitoring_interval             = 60
  monitoring_role_arn             = aws_iam_role.rds_enhanced_monitoring.arn

  depends_on = [aws_db_parameter_group.postgres]
}
