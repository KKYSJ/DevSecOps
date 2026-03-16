project_name = "secureflow"
environment = "dev"
aws_region = "ap-northeast-2"
single_nat_gateway = true
create_rds = false

# Node/FastAPI는 "S", Spring 코드를 그대로 쓰면 "N"이 필요합니다.
review_table_hash_key_type = "S"

# GitHub Actions OIDC는 저장소 정보가 확정된 뒤 켜는 편이 안전합니다.
create_github_oidc_role = true
# To enable GitHub Actions CD later:
github_org    = "KKYSJ"
github_repo   = "DevSecOps"
github_branch = "SEO"

# FastAPI는 Docker 이미지를 ECR에 먼저 push한 뒤 true로 바꾸는 것을 권장합니다.
enable_fastapi_service = true
fastapi_image_tag = "latest"
fastapi_desired_count = 1

# Node API service can be enabled after its image is pushed to ECR.
enable_node_service = true
node_image_tag = "latest"
node_desired_count = 1

# Spring API service can be enabled after its image is pushed to ECR.
enable_spring_service = true
spring_image_tag = "latest"
spring_desired_count = 1

# Frontend service can be enabled after its image is pushed to ECR.
enable_frontend_service = true
frontend_image_tag = "latest"
frontend_desired_count = 1
