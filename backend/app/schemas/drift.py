from pydantic import BaseModel


class DriftChange(BaseModel):
    setting: str
    change_type: str
    before: object | None = None
    after: object | None = None


class DriftRead(BaseModel):
    asset_id: int
    baseline_audit_id: int
    current_audit_id: int
    changes: list[DriftChange]
