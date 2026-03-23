project_name           = "secureflow"
environment            = "prod"
aws_region             = "ap-northeast-2"
single_nat_gateway     = false
create_rds             = true
db_multi_az            = true
db_deletion_protection = true
db_skip_final_snapshot = false

# Node/FastAPI는 "S", Spring 코드를 그대로 쓰면 "N"이 필요합니다.
review_table_hash_key_type = "S"

create_github_oidc_role     = true
create_github_oidc_provider = false
create_ecr_repositories     = false
github_org                  = "KKYSJ"
github_repo                 = "DevSecOps"
github_branch               = "main"

enable_fastapi_service = true
fastapi_image_tag      = "latest"
fastapi_desired_count  = 1

enable_node_service = true
node_image_tag      = "latest"
node_desired_count  = 1
node_use_rds        = true

enable_spring_service = true
spring_image_tag      = "latest"
spring_desired_count  = 1

enable_frontend_service = true
frontend_image_tag      = "latest"
frontend_desired_count  = 1
