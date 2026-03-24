from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from backend.app.api.router import api_router
from backend.app.core import models as llm_models  # Registers LLM-related tables.
from backend.app.core.database import Base, engine

# Register platform application models on the shared SQLAlchemy metadata.
import backend.app.models.cross_validation
import backend.app.models.isms_check
import backend.app.models.pipeline_run
import backend.app.models.scan
import backend.app.models.siem_event
import backend.app.models.tool_result
import backend.app.models.vulnerability

app = FastAPI(title="SecureFlow API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _run_column_migrations() -> None:
    """Apply additive column/index migrations for existing PostgreSQL tables."""
    migrations = [
        "ALTER TABLE scans ADD COLUMN IF NOT EXISTS tool VARCHAR(50) DEFAULT 'unknown'",
        "ALTER TABLE scans ADD COLUMN IF NOT EXISTS category VARCHAR(20)",
        "ALTER TABLE scans ADD COLUMN IF NOT EXISTS project_name VARCHAR(255) DEFAULT 'secureflow'",
        "ALTER TABLE scans ADD COLUMN IF NOT EXISTS raw_result JSONB",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS tool VARCHAR(50)",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS category VARCHAR(20)",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS line_number INTEGER",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cve_id VARCHAR(50)",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS status VARCHAR(32) DEFAULT 'OPEN'",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()",
        "ALTER TABLE pipeline_runs ALTER COLUMN name DROP NOT NULL",
        "ALTER TABLE pipeline_runs ALTER COLUMN name SET DEFAULT ''",
        "ALTER TABLE pipeline_runs ALTER COLUMN status SET DEFAULT 'scanning_phase1'",
        "ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS project_name VARCHAR(255) DEFAULT 'secureflow'",
        "ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS commit_hash VARCHAR(64)",
        "ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS branch VARCHAR(100) DEFAULT 'main'",
        "ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'scanning_phase1'",
        "ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS gate_result VARCHAR(20)",
        "ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS gate_score FLOAT",
        "ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS scan_ids JSONB",
        "ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()",
        "CREATE INDEX IF NOT EXISTS idx_pipeline_runs_commit_hash ON pipeline_runs(commit_hash)",
        "ALTER TABLE cross_validations ADD COLUMN IF NOT EXISTS commit_hash VARCHAR(64)",
        "ALTER TABLE cross_validations ADD COLUMN IF NOT EXISTS phase INTEGER",
        "CREATE INDEX IF NOT EXISTS idx_cross_validations_commit_hash ON cross_validations(commit_hash)",
    ]

    with engine.connect() as conn:
        for sql in migrations:
            try:
                conn.execute(text(sql))
            except Exception:
                pass
        conn.commit()


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)
    try:
        _run_column_migrations()
    except Exception:
        pass


@app.get("/")
def root():
    return {"message": "SecureFlow API running"}


@app.get("/health")
def health_check():
    return {"status": "ok"}


app.include_router(api_router)
