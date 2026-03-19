# Terraform Bootstrap And Base Stack

이 디렉터리는 AWS가 비어 있는 상태에서 아래 순서로 진행하도록 구성되어 있습니다.

`설치 -> AWS 인증 확인 -> bootstrap -> dev base infra -> app deploy`

중요한 점:

- `bootstrap` 단계와 `dev base infra` 단계는 서로 다른 Terraform 실행입니다.
- 그래서 `bootstrap/terraform.tfvars`와 `environments/dev/terraform.tfvars`는 쓰는 시점이 다릅니다.

## 지금 이 Terraform이 만드는 것

bootstrap 스택:

- Terraform state 저장용 S3 bucket
- Terraform lock용 DynamoDB table
- Terraform state 암호화용 KMS key

base 스택:

- VPC
- public / private app / private data subnet
- NAT gateway
- ALB
- ECS cluster
- ECR repositories
- frontend / uploads S3 bucket
- DynamoDB reviews table
- SQS queue
- SNS topic
- CloudWatch log groups
- IAM roles / KMS
- optional RDS
- optional GitHub Actions OIDC role

## 설치해야 하는 것

### 1. Terraform 또는 OpenTofu

둘 중 하나만 설치하면 됩니다.

Terraform:

```powershell
winget install HashiCorp.Terraform
terraform version
```

OpenTofu:

```powershell
winget install OpenTofu.Tofu
tofu version
```

이 문서 아래 예시는 `terraform` 기준입니다.  
OpenTofu를 쓰면 `terraform` 대신 `tofu`로 바꿔서 실행하면 됩니다.

### 2. AWS CLI

```powershell
winget install Amazon.AWSCLI
aws --version
```

## AWS에서 미리 준비해야 하는 것

### 1. AWS 계정

- 가능하면 루트 계정이 아니라 관리자 권한이 있는 IAM 사용자 또는 AWS SSO 계정 사용
- 시작은 `dev` 환경 기준 추천

### 2. 필요한 권한

최소한 아래 리소스를 만들 수 있어야 합니다.

- `S3`
- `DynamoDB`
- `KMS`
- `VPC`
- `EC2`
- `ECR`
- `ECS`
- `IAM`
- `CloudWatch`
- `SNS`
- `SQS`
- `RDS`
- `Secrets Manager`

## AWS CLI 연동

### 방법 1. Access Key

```powershell
aws configure
```

입력값:

- AWS Access Key ID
- AWS Secret Access Key
- Default region name: `ap-northeast-2`
- Default output format: `json`

### 방법 2. AWS SSO

```powershell
aws configure sso
aws sso login
```

## AWS 연동 확인

```powershell
aws sts get-caller-identity
```

계정 ID, ARN, UserId가 나오면 준비 완료입니다.

## 1단계: bootstrap 설정

이 단계는 Terraform state를 저장할 S3와 lock table을 만드는 단계입니다.

사용 파일:

- [bootstrap/terraform.tfvars.example](bootstrap/terraform.tfvars.example)
- 실제 실행 파일: `bootstrap/terraform.tfvars`

복사:

```powershell
cd infra/terraform/bootstrap
Copy-Item terraform.tfvars.example terraform.tfvars
```

기본적으로 아래 3줄만 있어도 됩니다.

```tfvars
project_name = "secureflow"
environment  = "shared"
aws_region   = "ap-northeast-2"
```

처음에는 보통 추가로 더 쓸 필요 없습니다.

선택적으로만 넣는 값:

- `state_bucket_name`
- `lock_table_name`
- `force_destroy`
- `default_tags`

## 2단계: dev base infra 설정

이 단계는 bootstrap 이후에 실행하는 "실제 AWS 인프라" 설정입니다.

사용 파일:

- [environments/dev/terraform.tfvars](environments/dev/terraform.tfvars)

현재 기본값:

- `project_name = "secureflow"`
- `environment = "dev"`
- `aws_region = "ap-northeast-2"`
- `single_nat_gateway = true`
- `create_rds = false`
- `review_table_hash_key_type = "S"`

## 처음 시작할 때 추천값

처음 AWS 연결 테스트라면 아래처럼 가는 게 가장 무난합니다.

- `environment = "dev"`
- `aws_region = "ap-northeast-2"`
- `single_nat_gateway = true`
- `create_rds = false`
- `review_table_hash_key_type = "S"`

이 추천값이 좋은 이유:

- `single_nat_gateway = true`
  - dev 비용을 줄여줍니다.
- `create_rds = false`
  - 처음부터 RDS 비용과 설정 복잡도를 올리지 않습니다.
- `review_table_hash_key_type = "S"`
  - Node / FastAPI 기준으로 바로 맞습니다.

## 여기서 꼭 결정해야 하는 것

### 1. 어떤 API를 먼저 올릴지

- Node 또는 FastAPI를 먼저 올릴 거면 `review_table_hash_key_type = "S"`
- Spring을 먼저 올릴 거면 현재 코드 기준 `review_table_hash_key_type = "N"`

### 2. RDS를 지금 만들지

- 비용 아끼고 먼저 VPC/ECS/ECR만 확인할 거면 `create_rds = false`
- MySQL까지 바로 붙여보고 싶으면 `create_rds = true`

## 결론

처음 시작할 때는 이렇게 이해하면 됩니다.

- `bootstrap/terraform.tfvars`
  - 지금은 3줄만 있으면 충분
- `environments/dev/terraform.tfvars`
  - 이건 bootstrap 끝난 뒤 base infra 적용할 때 보는 파일
  - 처음엔 기본값 그대로 시작해도 괜찮음

## 실제 실행 순서

### 1. bootstrap 적용

```powershell
cd C:\Users\User\Desktop\secureflow\secureflow\infra\terraform\bootstrap
terraform init
terraform apply -var-file="terraform.tfvars"
```

기록해둘 출력값:

- state bucket name
- lock table name
- KMS key ARN

### 2. base infra backend 연결

```powershell
cd C:\Users\User\Desktop\secureflow\secureflow\infra\terraform
terraform init `
  -backend-config="bucket=<bootstrap-output-bucket>" `
  -backend-config="key=envs/dev/terraform.tfstate" `
  -backend-config="region=ap-northeast-2" `
  -backend-config="dynamodb_table=<bootstrap-output-lock-table>" `
  -backend-config="encrypt=true"
```

### 3. dev base infra 적용

```powershell
terraform apply -var-file="environments/dev/terraform.tfvars"
```

## FastAPI 하나만 먼저 올리는 순서

여기부터는 `dev base infra`까지 끝난 뒤에 진행합니다.

### 1. Docker 설치

FastAPI 이미지를 만들려면 Docker Desktop이 필요합니다.

확인:

```powershell
docker --version
```

### 2. 현재 Terraform 변경사항 한 번 반영

FastAPI ECS service 관련 코드와 output을 반영하기 위해 한 번 더 apply 합니다.  
이때는 아직 `enable_fastapi_service = false` 상태로 두면 됩니다.

```powershell
cd C:\Users\User\Desktop\secureflow\secureflow\infra\terraform
terraform apply -var-file="environments/dev/terraform.tfvars"
```

### 3. FastAPI 이미지 URI 확인

```powershell
terraform output -raw fastapi_image_uri
```

예시:

```text
213026893250.dkr.ecr.ap-northeast-2.amazonaws.com/api-server-fastapi:latest
```

### 4. ECR 로그인

```powershell
$FASTAPI_IMAGE = terraform output -raw fastapi_image_uri
$REGISTRY = ($FASTAPI_IMAGE -split "/")[0]
aws ecr get-login-password --region ap-northeast-2 | docker login --username AWS --password-stdin $REGISTRY
```

### 5. FastAPI 이미지 build

```powershell
cd C:\Users\User\Desktop\secureflow\secureflow
docker build -t api-server-fastapi:latest app/api-server-fastapi
```

### 6. ECR tag / push

```powershell
$FASTAPI_IMAGE = terraform output -raw fastapi_image_uri
docker tag api-server-fastapi:latest $FASTAPI_IMAGE
docker push $FASTAPI_IMAGE
```

### 7. FastAPI service 활성화

[environments/dev/terraform.tfvars](environments/dev/terraform.tfvars)에서 아래 값을 확인합니다.

```tfvars
enable_fastapi_service = true
fastapi_image_tag = "latest"
fastapi_desired_count = 1
```

### 8. ECS service 생성 apply

```powershell
cd C:\Users\User\Desktop\secureflow\secureflow\infra\terraform
terraform apply -var-file="environments/dev/terraform.tfvars"
```

### 9. 정상 동작 확인

- ECS Service에 task 1개가 Running 상태인지 확인
- Target Group health check가 Healthy인지 확인
- 아래 주소 응답 확인

```text
http://<alb_dns_name>/api/health
```

## 적용 후 확인할 것

- VPC 생성 여부
- subnet 생성 여부
- ALB 생성 여부
- ECS cluster 생성 여부
- ECR repositories 생성 여부
- S3 bucket 생성 여부
- DynamoDB / SQS / SNS 생성 여부

## 아직 안 되는 것

아직 아래는 준비되지 않았습니다.

- ECS task definition
- ECS service
- ALB listener rule
- 컨테이너 빌드 / 푸시
- frontend 공개 배포
- Redis / ElastiCache
- CloudTrail / GuardDuty / Security Hub / Config

즉, 지금 단계는 "AWS 기반 인프라 생성"까지입니다.

## 관련 문서

- [Architecture Index](../../docs/architecture/README.md)
- [AWS Terraform Flow](../../docs/architecture/aws-terraform-flow.md)
- [Bootstrap Guide](bootstrap/README.md)
