from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import JSON
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import uuid, os
import datetime

# Engine setup
postgres_url = os.getenv("DATABASE_URL")
sqlite_url = "sqlite:///./local.db"

try:
    if postgres_url:
        engine = create_engine(
            postgres_url,
            connect_args={"sslmode": "require"} if "render" in postgres_url else {},
            echo=False,
        )
    else:
        raise ValueError("DATABASE_URL not set")
except Exception as e:
    print(f"⚠️ Falling back to SQLite due to: {e}")
    engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ScanResult(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    uploaded_filename = Column(String)
    ecosystem = Column(String)
    results = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

def init_db():
    Base.metadata.create_all(bind=engine)

init_db()
