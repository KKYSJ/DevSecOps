variable "project_name" {
  description = "프로젝트 이름"
  type        = string
  default     = "secureflow"
}

variable "environment" {
  description = "배포 환경(dev/stage/prod)"
  type        = string
  default     = "prod"
}

variable "aws_region" {
  description = "AWS 리전"
  type        = string
  default     = "ap-northeast-2"
}

variable "vpc_cidr" {
  description = "VPC CIDR"
  type        = string
  default     = "10.30.0.0/16"
}

variable "frontend_image_tag" {
  description = "Frontend ECR 이미지 태그"
  type        = string
  default     = "latest"
}

variable "backend_image_tag" {
  description = "Backend ECR 이미지 태그"
  type        = string
  default     = "latest"
}

variable "worker_image_tag" {
  description = "Worker ECR 이미지 태그"
  type        = string
  default     = "latest"
}

variable "frontend_cpu" {
  description = "Frontend task CPU"
  type        = number
  default     = 256
}

variable "frontend_memory" {
  description = "Frontend task Memory(MiB)"
  type        = number
  default     = 512
}

variable "backend_cpu" {
  description = "Backend task CPU"
  type        = number
  default     = 512
}

variable "backend_memory" {
  description = "Backend task Memory(MiB)"
  type        = number
  default     = 1024
}

variable "worker_cpu" {
  description = "Worker task CPU"
  type        = number
  default     = 512
}

variable "worker_memory" {
  description = "Worker task Memory(MiB)"
  type        = number
  default     = 1024
}

variable "frontend_desired_count" {
  description = "Frontend desired count"
  type        = number
  default     = 1
}

variable "backend_desired_count" {
  description = "Backend desired count"
  type        = number
  default     = 1
}

variable "worker_desired_count" {
  description = "Worker desired count"
  type        = number
  default     = 1
}

variable "frontend_min_capacity" {
  description = "Frontend autoscaling min"
  type        = number
  default     = 1
}

variable "frontend_max_capacity" {
  description = "Frontend autoscaling max"
  type        = number
  default     = 2
}

variable "backend_min_capacity" {
  description = "Backend autoscaling min"
  type        = number
  default     = 1
}

variable "backend_max_capacity" {
  description = "Backend autoscaling max"
  type        = number
  default     = 2
}

variable "enable_autoscaling" {
  description = "Frontend/Backend ECS autoscaling 활성화 여부"
  type        = bool
  default     = false
}

variable "cpu_scale_target" {
  description = "ECS target tracking CPU 목표값"
  type        = number
  default     = 60
}

variable "db_name" {
  description = "RDS DB 이름"
  type        = string
  default     = "secureflow"
}

variable "db_username" {
  description = "RDS 마스터 사용자"
  type        = string
  default     = "secureflow"
}

variable "db_instance_class" {
  description = "RDS 인스턴스 클래스"
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  description = "RDS 기본 스토리지(GB)"
  type        = number
  default     = 20
}

variable "db_max_allocated_storage" {
  description = "RDS autoscaling 최대 스토리지(GB)"
  type        = number
  default     = 100
}

variable "db_engine_version" {
  description = "PostgreSQL 버전"
  type        = string
  default     = "16.6"
}

variable "db_backup_retention_period" {
  description = "RDS 백업 보존 기간(일)"
  type        = number
  default     = 0
}

variable "db_multi_az" {
  description = "RDS Multi-AZ 여부"
  type        = bool
  default     = false
}

variable "redis_node_type" {
  description = "ElastiCache Redis 노드 타입"
  type        = string
  default     = "cache.t4g.micro"
}

variable "redis_engine_version" {
  description = "Redis 엔진 버전"
  type        = string
  default     = "7.1"
}

variable "reports_bucket_name" {
  description = "리포트 저장용 S3 버킷명. null이면 자동 생성"
  type        = string
  default     = null
}

variable "app_secret_name" {
  description = "앱 환경변수용 Secrets Manager 이름. null이면 자동 생성"
  type        = string
  default     = null
}

variable "gemini_api_key" {
  description = "Gemini API 키"
  type        = string
  sensitive   = true
  default     = null
}

variable "gemini_model" {
  description = "Gemini 모델명"
  type        = string
  default     = "gemini-3.1-flash-lite"
}

variable "openai_api_key" {
  description = "OpenAI API 키"
  type        = string
  sensitive   = true
  default     = null
}

variable "sonarqube_url" {
  description = "외부 SonarQube URL(선택)"
  type        = string
  default     = ""
}

variable "sonarqube_token" {
  description = "외부 SonarQube 토큰(선택)"
  type        = string
  sensitive   = true
  default     = null
}

variable "alarm_email" {
  description = "CloudWatch 알람 구독 이메일(선택)"
  type        = string
  default     = null
}

variable "log_retention_in_days" {
  description = "CloudWatch Logs 보존 기간"
  type        = number
  default     = 365
}

variable "acm_certificate_arn" {
  description = "HTTPS용 ACM 인증서 ARN. null이면 HTTP만 생성"
  type        = string
  default     = null
}

variable "enable_waf" {
  description = "ALB 앞단 WAF 활성화"
  type        = bool
  default     = true
}

variable "waf_rate_limit" {
  description = "5분 기준 IP당 rate limit"
  type        = number
  default     = 2000
}

variable "tags" {
  description = "추가 태그"
  type        = map(string)
  default     = {}
}
