resource "random_password" "master" {
  length  = 24
  special = false
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.identifier}-subnet-group"
  subnet_ids = var.subnet_ids

  tags = merge(var.tags, { Name = "${var.identifier}-subnet-group" })
}

resource "aws_db_instance" "this" {
  identifier                   = var.identifier
  allocated_storage            = var.allocated_storage
  max_allocated_storage        = var.max_allocated_storage
  storage_type                 = "gp3"
  engine                       = "mysql"
  engine_version               = var.engine_version
  instance_class               = var.instance_class
  db_name                      = var.db_name
  username                     = var.username
  password                     = random_password.master.result
  db_subnet_group_name         = aws_db_subnet_group.this.name
  vpc_security_group_ids       = var.vpc_security_group_ids
  multi_az                     = var.multi_az
  publicly_accessible          = var.publicly_accessible
  backup_retention_period      = var.backup_retention_period
  deletion_protection          = var.deletion_protection
  skip_final_snapshot          = var.skip_final_snapshot
  storage_encrypted            = true
  kms_key_id                   = var.kms_key_arn
  auto_minor_version_upgrade   = true
  apply_immediately            = var.apply_immediately
  performance_insights_enabled = false

  tags = merge(var.tags, { Name = var.identifier })
}

resource "aws_secretsmanager_secret" "this" {
  name                    = "${var.identifier}-credentials"
  recovery_window_in_days = 0

  tags = merge(var.tags, { Name = "${var.identifier}-credentials" })
}

resource "aws_secretsmanager_secret_version" "this" {
  secret_id = aws_secretsmanager_secret.this.id
  secret_string = jsonencode({
    engine   = "mysql"
    host     = aws_db_instance.this.address
    port     = aws_db_instance.this.port
    dbname   = var.db_name
    username = var.username
    password = random_password.master.result
  })
}
