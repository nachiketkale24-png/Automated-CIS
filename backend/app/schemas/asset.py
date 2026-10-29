from datetime import datetime
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field


# ── Asset-type validation ──────────────────────────────────────────────
class AssetType(str, Enum):
    windows = "windows"
    linux = "linux"
    firewall = "firewall"
    router = "router"
    switch = "switch"
    network_device = "network_device"


class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    asset_type: AssetType = AssetType.network_device
    hostname: str = Field(min_length=1, max_length=255)
    platform: str | None = None


class AssetRead(BaseModel):
    id: int
    name: str
    asset_type: str
    hostname: str
    platform: str | None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)
