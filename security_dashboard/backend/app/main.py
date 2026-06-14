from __future__ import annotations

from functools import lru_cache

from fastapi import Depends, FastAPI, Header, HTTPException, Request

from .auth import verify_ingestion
from .config import Settings, get_settings
from .models import MonitorReport
from .repository import MongoRunRepository


@lru_cache
def get_repository() -> MongoRunRepository:
    settings = get_settings()
    return MongoRunRepository(settings.mongodb_uri, settings.mongodb_database, settings.retention_days)


def create_app() -> FastAPI:
    get_settings()
    app = FastAPI(title="Security Pipeline Monitor", version="1.0.0")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/api/v1/runs", status_code=202)
    async def ingest_run(
        request: Request,
        x_monitor_timestamp: str = Header(...),
        x_monitor_signature: str = Header(...),
        repository: MongoRunRepository = Depends(get_repository),
        current_settings: Settings = Depends(get_settings),
    ) -> dict:
        body = await request.body()
        signature_id = verify_ingestion(
            body,
            x_monitor_timestamp,
            x_monitor_signature,
            current_settings.security_monitor_secret,
        )
        if not repository.claim_signature(signature_id):
            raise HTTPException(409, "Ingestion request already processed")
        report = MonitorReport.model_validate_json(body)
        if not report.run_id:
            raise HTTPException(422, "github.run_id is required")
        saved = repository.upsert(report.model_dump(mode="python"))
        return {"accepted": True, "run_id": saved["run_id"]}

    return app


app = create_app()
