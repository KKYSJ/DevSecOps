// main.tf - 보안 취약점 테스트용 (IaC 탐지 대상)

// [IaC] Security Group - 모든 포트 개방
resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-sg"
  description = "Intentionally vulnerable SG for testing"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

// [IaC] S3 버킷 - 암호화 없음, 퍼블릭 접근 허용
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "secureflow-vulnerable-test"
}

resource "aws_s3_bucket_public_access_block" "vulnerable_public" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

// [IaC] RDS - 암호화 없음, 퍼블릭 접근
resource "aws_db_instance" "vulnerable_db" {
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  db_name              = "testdb"
  username             = "admin"
  password             = "password123!"
  publicly_accessible  = true
  storage_encrypted    = false
  skip_final_snapshot  = true
}

// [IaC] EC2 - 메타데이터 서비스 v1 허용
resource "aws_instance" "vulnerable_ec2" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }
}

// [IaC] IAM 정책 - 와일드카드 권한
resource "aws_iam_role_policy" "vulnerable_policy" {
  name = "vulnerable-policy"
  role = "some-role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

// [IaC] CloudWatch 로그 그룹 - 보존 기간 미설정, 암호화 없음
resource "aws_cloudwatch_log_group" "vulnerable_logs" {
  name = "/app/vulnerable-logs"
}

// [IaC] EBS 볼륨 - 암호화 없음
resource "aws_ebs_volume" "vulnerable_volume" {
  availability_zone = "ap-northeast-2a"
  size              = 20
  encrypted         = false
}
