from backend.app.core.celery_app import celery_app


@celery_app.task(name="analysis.worker")
def run_task(payload=None):
    return {"worker": "analysis_worker", "payload": payload}
