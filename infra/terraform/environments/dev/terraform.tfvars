project_name = "secureflow"
environment = "dev"
aws_region = "ap-northeast-2"
single_nat_gateway = true
create_rds = false

# Node/FastAPI는 "S", Spring 코드를 그대로 쓰면 "N"이 필요합니다.
review_table_hash_key_type = "S"

# GitHub Actions OIDC는 저장소 정보가 확정된 뒤 켜는 편이 안전합니다.
create_github_oidc_role = false

# FastAPI는 Docker 이미지를 ECR에 먼저 push한 뒤 true로 바꾸는 것을 권장합니다.
enable_fastapi_service = true
fastapi_image_tag = "latest"
fastapi_desired_count = 1
