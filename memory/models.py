from sqlalchemy import Column, String, Text, DateTime, JSON, Integer, Float
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


class ProvenanceLogDB(Base):
    """Phase 9 — durable mirror of firewall/provenance.py's in-memory provenance_logs list, so
    audit history survives a process restart. The in-memory list stays the primary read path
    (unchanged, zero behavior risk); this is a best-effort write-through, never a hard
    dependency of any request path."""
    __tablename__ = "provenance_logs_db"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    operation = Column(String, nullable=False)
    memory_id = Column(String, nullable=True)
    agent_id = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    outcome = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)
    request_id = Column(String, nullable=True)
    classification = Column(String, nullable=True)
    risk_score = Column(Float, nullable=True)
    trust_before = Column(Float, nullable=True)
    trust_after = Column(Float, nullable=True)
    final_decision = Column(String, nullable=True)
    policy_rule_triggered = Column(String, nullable=True)


class AgentTrustDB(Base):
    """Phase 9 — durable mirror of firewall/trust_engine.py's in-memory agent_history dict, so
    trust scores survive a process restart. Same best-effort write-through approach as above."""
    __tablename__ = "agent_trust_db"

    agent_id = Column(String, primary_key=True)
    injection_attempts = Column(Integer, default=0)
    poisoning_attempts = Column(Integer, default=0)
    total_reads = Column(Integer, default=0)
    total_writes = Column(Integer, default=0)
    role_violations = Column(Integer, default=0)
    total_actions = Column(Integer, default=0)
    role = Column(String, default="AGENT")
    last_violation_time = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)