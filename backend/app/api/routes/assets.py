from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.schemas.asset import AssetCreate, AssetRead
from app.services.persistence import create_asset, list_assets

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=list[AssetRead])
def get_assets(db: Session = Depends(get_db)):
    return list_assets(db)


@router.post("", response_model=AssetRead, status_code=201)
def post_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    return create_asset(db, payload)
