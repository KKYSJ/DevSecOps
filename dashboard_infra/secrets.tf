resource "aws_secretsmanager_secret" "app" {
  name                    = local.app_secret_name
  recovery_window_in_days = 7
  kms_key_id              = aws_kms_key.app.arn
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id = aws_secretsmanager_secret.app.id

  secret_string = jsonencode({
    DATABASE_URL          = "postgresql+psycopg2://${var.db_username}:${random_password.db_password.result}@${aws_db_instance.postgres.address}:${aws_db_instance.postgres.port}/${var.db_name}"
    REDIS_URL             = "rediss://:${random_password.redis_auth_token.result}@${aws_elasticache_replication_group.redis.primary_endpoint_address}:${aws_elasticache_replication_group.redis.port}/0"
    CELERY_BROKER_URL     = "rediss://:${random_password.redis_auth_token.result}@${aws_elasticache_replication_group.redis.primary_endpoint_address}:${aws_elasticache_replication_group.redis.port}/0"
    CELERY_RESULT_BACKEND = "rediss://:${random_password.redis_auth_token.result}@${aws_elasticache_replication_group.redis.primary_endpoint_address}:${aws_elasticache_replication_group.redis.port}/1"
    GEMINI_API_KEY        = var.gemini_api_key
    GEMINI_MODEL          = var.gemini_model
    OPENAI_API_KEY        = var.openai_api_key
    SONARQUBE_TOKEN       = var.sonarqube_token
  })

  depends_on = [
    aws_db_instance.postgres,
    aws_elasticache_replication_group.redis
  ]
}
