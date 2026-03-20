resource "random_password" "redis_auth_token" {
  length           = 32
  special          = false
}

resource "aws_elasticache_subnet_group" "main" {
  name       = "${local.name}-redis-subnets"
  subnet_ids = [for subnet in aws_subnet.private_data : subnet.id]
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = replace("${local.name}-redis", "-", "")
  description                = "SecureFlow Celery/Redis"
  engine                     = "redis"
  engine_version             = var.redis_engine_version
  node_type                  = var.redis_node_type
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.main.name
  security_group_ids         = [aws_security_group.redis.id]
  num_cache_clusters         = 1
  automatic_failover_enabled = false
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis_auth_token.result
  kms_key_id                 = aws_kms_key.app.arn
  snapshot_retention_limit   = 3
  apply_immediately          = true
}
