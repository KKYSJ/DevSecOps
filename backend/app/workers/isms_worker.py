from backend.app.core.celery_app import celery_app


@celery_app.task(name="isms.worker")
def run_task(payload=None):
    return {"worker": "isms_worker", "payload": payload}
