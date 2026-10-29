from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, String, Float, Boolean, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class Audit(Base):
    __tablename__ = "audits"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="COMPLETED")
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_simulated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    benchmark_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    asset: Mapped["Asset"] = relationship(back_populates="audits")
    findings: Mapped[list["Finding"]] = relationship(back_populates="audit", cascade="all, delete-orphan")
    snapshots: Mapped[list["Snapshot"]] = relationship(back_populates="audit", cascade="all, delete-orphan")
