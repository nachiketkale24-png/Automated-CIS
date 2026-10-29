from app.db.base import Base
from app.db.session import engine
from app import models  # noqa: F401 - imports model classes for metadata registration


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    init_db()
    print("Database tables are ready.")
