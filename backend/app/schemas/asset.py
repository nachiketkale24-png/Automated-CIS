from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    asset_type: str = "network_device"
    hostname: str = Field(min_length=1, max_length=255)
    platform: str | None = None


class AssetRead(AssetCreate):
    id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)
