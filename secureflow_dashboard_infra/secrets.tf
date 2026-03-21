locals {
  bootstrap_external_api_secret = anytrue([
    var.gemini_api_key != null,
    var.openai_api_key != null,
    var.sonar_token != null
  ])
}

resource "aws_secretsmanager_secret" "db" {
  name                    = local.db_secret_name
  recovery_window_in_days = 7
  kms_key_id              = aws_kms_key.app.arn
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id = aws_secretsmanager_secret.db.id

  secret_string = jsonencode({
    DATABASE_URL = "postgresql+psycopg2://${var.db_username}:${random_password.db_password.result}@${aws_db_instance.postgres.address}:${aws_db_instance.postgres.port}/${var.db_name}"
  })

  depends_on = [aws_db_instance.postgres]
}

resource "aws_secretsmanager_secret" "redis" {
  name                    = local.redis_secret_name
  recovery_window_in_days = 7
  kms_key_id              = aws_kms_key.app.arn
}

resource "aws_secretsmanager_secret_version" "redis" {
  secret_id = aws_secretsmanager_secret.redis.id

  secret_string = jsonencode({
    REDIS_URL             = "rediss://:${random_password.redis_auth_token.result}@${aws_elasticache_replication_group.redis.primary_endpoint_address}:${aws_elasticache_replication_group.redis.port}/0"
    CELERY_BROKER_URL     = "rediss://:${random_password.redis_auth_token.result}@${aws_elasticache_replication_group.redis.primary_endpoint_address}:${aws_elasticache_replication_group.redis.port}/0"
    CELERY_RESULT_BACKEND = "rediss://:${random_password.redis_auth_token.result}@${aws_elasticache_replication_group.redis.primary_endpoint_address}:${aws_elasticache_replication_group.redis.port}/1"
  })

  depends_on = [aws_elasticache_replication_group.redis]
}

resource "aws_secretsmanager_secret" "external_api" {
  name                    = local.external_api_secret_name
  recovery_window_in_days = 7
  kms_key_id              = aws_kms_key.app.arn
}

resource "aws_secretsmanager_secret_version" "external_api_bootstrap" {
  count = local.bootstrap_external_api_secret ? 1 : 0

  secret_id = aws_secretsmanager_secret.external_api.id

  secret_string = jsonencode({
    GEMINI_API_KEY = coalesce(var.gemini_api_key, "")
    OPENAI_API_KEY = coalesce(var.openai_api_key, "")
    SONAR_TOKEN    = coalesce(var.sonar_token, "")
  })
}
