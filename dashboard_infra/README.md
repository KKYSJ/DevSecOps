# SecureFlow AWS Terraform (보안 우선 수정본)

이 Terraform 코드는 현재 프로젝트를 AWS 상에 다음 구조로 배포하도록 작성되었습니다.

- **Frontend**: ECS Fargate (사설 서브넷) + Public ALB
- **Backend API**: ECS Fargate (사설 서브넷)
- **Worker**: ECS Fargate (사설 서브넷, Celery)
- **DB**: Amazon RDS PostgreSQL (사설 데이터 서브넷)
- **Queue/Cache**: Amazon ElastiCache for Redis (사설 데이터 서브넷)
- **Artifact Storage**: Amazon S3
- **Image Registry**: Amazon ECR
- **Protection / Monitoring**: AWS WAF + CloudWatch Logs/Alarms + VPC Flow Logs

이번 수정본은 Checkov 결과 중 **운영 전에 먼저 손봐야 하는 항목**을 우선 반영했습니다.

## 먼저 반영한 보안 사항

- ECR 이미지 태그를 immutable 로 변경
- ECR 저장소를 KMS CMK로 암호화
- RDS PostgreSQL 로그 export 활성화
- RDS Enhanced Monitoring 활성화
- RDS Performance Insights KMS CMK 적용
- Redis in-transit encryption + auth token + CMK 적용
- Secrets Manager CMK 적용
- CloudWatch Log Group KMS 암호화 + 365일 보존
- WAF Logging 추가
- ALB Access Logging 추가
- VPC 기본 Security Group 차단
- 보안 그룹 egress 범위 축소
- S3 reports 버킷 기본 암호화를 SSE-KMS 로 변경
- S3 lifecycle 에 abort_incomplete_multipart_upload 추가

## 아직 의도적으로 남겨둔 항목

- RDS IAM DB 인증: 애플리케이션 연결 방식 변경 부담이 있어 우선 미적용
- Redis Multi-AZ / automatic failover: 작은 내부용 서버 비용을 고려해 우선 미적용
- HTTPS 강제: ACM 인증서를 넣으면 해결되며, 현재는 HTTP-only 내부 테스트도 허용
- S3 CRR / Event notification: 필수 보안보다 운영 확장성 영역이라 후순위
- ALB → ECS 내부 구간 HTTPS: 같은 VPC 내부 통신이라 후순위
- Secrets rotation: 실제 rotation Lambda 설계가 필요해 후순위

## 적용 방법

```bash
cd dashboard_infra
cp terraform.tfvars.example terraform.tfvars
# 값 수정
terraform init
terraform plan
terraform apply
```
