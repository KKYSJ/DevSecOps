"""
AWS SDK 클라이언트 초기화 모듈
- 필요할 때만 클라이언트를 생성 (Lazy initialization)
- S3, DynamoDB, SQS, SNS 클라이언트 제공
"""

import boto3
from app.config.settings import settings

# 클라이언트 캐시 (한 번만 생성)
_s3_client = None
_dynamodb_resource = None
_sqs_client = None
_sns_client = None


def get_s3_client():
    """S3 클라이언트 반환"""
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3", region_name=settings.S3_REGION)
        print("[AWS] S3 클라이언트 생성 완료")
    return _s3_client


def get_dynamodb_resource():
    """DynamoDB 리소스 반환"""
    global _dynamodb_resource
    if _dynamodb_resource is None:
        _dynamodb_resource = boto3.resource(
            "dynamodb", region_name=settings.DYNAMODB_REGION
        )
        print("[AWS] DynamoDB 리소스 생성 완료")
    return _dynamodb_resource


def get_sqs_client():
    """SQS 클라이언트 반환"""
    global _sqs_client
    if _sqs_client is None:
        _sqs_client = boto3.client("sqs", region_name=settings.S3_REGION)
        print("[AWS] SQS 클라이언트 생성 완료")
    return _sqs_client


def get_sns_client():
    """SNS 클라이언트 반환"""
    global _sns_client
    if _sns_client is None:
        _sns_client = boto3.client("sns", region_name=settings.S3_REGION)
        print("[AWS] SNS 클라이언트 생성 완료")
    return _sns_client
