from sqlalchemy import String, JSON, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(30), nullable=False, default="Medium")
    benchmark: Mapped[str | None] = mapped_column(String(120), nullable=True)
    benchmark_version: Mapped[str | None] = mapped_column(String(60), nullable=True)
    definition_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
