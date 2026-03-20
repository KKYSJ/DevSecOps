terraform {
  backend "s3" {
    bucket         = "secureflow-terraform-state-213026893250"
    key            = "dashboard_infra/terraform.tfstate"
    region         = "ap-northeast-2"
    dynamodb_table = "secureflow-terraform-locks"
    encrypt        = true
  }
}
