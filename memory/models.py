from sqlalchemy import Column, String, Text, DateTime, JSON
from sqlalchemy.orm import declarative_base
from pgvector.sqlalchemy import Vector
from datetime import datetime
import uuid

Base = declarative_base()

class Memory(Base):
    __tablename__ = "memories"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, nullable=False, index=True)
    content = Column(Text, nullable=False)
    embedding = Column(Vector(384), nullable=False)
    namespace = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    extra_metadata = Column(JSON, default={})