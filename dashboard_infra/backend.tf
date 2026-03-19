# 권장: 실제 운영에서는 로컬 상태 대신 S3 + DynamoDB(or S3 native locking) 원격 상태를 사용하세요.
# 아래는 예시이며, bucket/key/region은 `terraform init -backend-config=...` 로 주입하는 방식을 추천합니다.
#
# terraform {
#   backend "s3" {}
# }
