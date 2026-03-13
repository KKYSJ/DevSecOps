from celery import Celery
from backend.app.config import settings

celery_app = Celery(
    "secureflow",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)
