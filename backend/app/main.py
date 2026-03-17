from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.router import api_router
from backend.app.core import models  # Registers SQLAlchemy models before create_all.
from backend.app.core.database import Base, engine

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SecureFlow API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"message": "SecureFlow API running"}


@app.get("/health")
def health_check():
    return {"status": "ok"}


app.include_router(api_router)
