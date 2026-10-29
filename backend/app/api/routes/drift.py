from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.services.drift_service import compare_latest_snapshots

router = APIRouter(prefix="/audits", tags=["drift"])


@router.get("/{audit_id}/drift")
def get_drift(audit_id: int, db: Session = Depends(get_db)):
    return compare_latest_snapshots(db, audit_id)
