# Deployment

이 프로젝트는 `dashboard_infra` 기준으로 AWS에 배포하도록 구성되었습니다.

## 배포 구조

- Frontend: ECS Fargate + ALB
- Backend API: ECS Fargate
- Worker: ECS Fargate
- DB: RDS PostgreSQL
- Cache/Queue: ElastiCache Redis
- Storage: S3
- Image Registry: ECR
- Protection/Monitoring: WAF, CloudWatch, VPC Flow Logs

자세한 내용은 `dashboard_infra/README.md` 를 참고하세요.
