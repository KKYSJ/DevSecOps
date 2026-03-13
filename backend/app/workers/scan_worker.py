from backend.app.core.celery_app import celery_app


@celery_app.task(name="scan.worker")
def run_task(payload=None):
    return {"worker": "scan_worker", "payload": payload}
