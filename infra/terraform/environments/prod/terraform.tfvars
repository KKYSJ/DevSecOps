project_name = "secureflow"
environment = "prod"
aws_region = "ap-northeast-2"
single_nat_gateway = false
create_rds = true
db_multi_az = true
db_deletion_protection = true
db_skip_final_snapshot = false

# Node/FastAPI는 "S", Spring 코드를 그대로 쓰면 "N"이 필요합니다.
review_table_hash_key_type = "S"

create_github_oidc_role = false
