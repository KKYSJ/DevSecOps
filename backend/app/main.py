from fastapi import FastAPI
from app.core.database import engine, Base
from app.core import models
from app.routers.scan_results import router as scan_results_router
from app.routers.crosscheck import router as crosscheck_router

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.include_router(scan_results_router)
app.include_router(crosscheck_router)

@app.get("/")
def root():
    return {"message": "DevSecOps API running"}