from sqlalchemy import Column, String, Text, DateTime, JSON, Integer
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
    version = Column(Integer, nullable=False, default=1)  # Phase 7: bumped on every update/rollback
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class MemoryVersion(Base):
    """Phase 7 — memory versioning & rollback. One row per prior version of a Memory, so an
    admin can inspect history and restore a safe earlier version if a memory was poisoned."""
    __tablename__ = "memory_versions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    memory_id = Column(String, nullable=False, index=True)
    version_number = Column(Integer, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    agent_id = Column(String, nullable=False)
    operation = Column(String, nullable=False)  # "create" | "update" | "rollback"
    previous_content_hash = Column(String, nullable=True)
    current_content_hash = Column(String, nullable=True)
    change_reason = Column(String, nullable=True)
    # Encrypted snapshot of the content AT this version — not in the playbook's minimum field
    # list, but required to actually restore content on rollback rather than just recording that
    # a change happened.
    content_snapshot = Column(Text, nullable=False)