from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer
from sqlalchemy import select, delete
from typing import Optional
import uuid

from database import SessionLocal
from models import Memory
from encryption import encrypt, decrypt

app = FastAPI(title="SecureMem Memory API")

model = SentenceTransformer('all-MiniLM-L6-v2')


class WriteRequest(BaseModel):
    agent_id: str
    content: str
    namespace: str
    metadata: Optional[dict] = {}


class SearchRequest(BaseModel):
    agent_id: str
    query: str
    namespace: str
    top_k: int = 5


class DeleteRequest(BaseModel):
    memory_id: str


@app.post("/memory/write")
def write_memory(req: WriteRequest):
    embedding = model.encode(req.content).tolist()
    db = SessionLocal()
    try:
        mem = Memory(
            id=str(uuid.uuid4()),
            agent_id=req.agent_id,
            content=encrypt(req.content),
            embedding=embedding,
            namespace=req.namespace,
            extra_metadata=req.metadata
        )
        db.add(mem)
        db.commit()
        return {"status": "stored", "id": mem.id}
    finally:
        db.close()


@app.get("/memory/search")
def search_memory(agent_id: str, query: str, namespace: str, top_k: int = 5):
    embedding = model.encode(query).tolist()
    db = SessionLocal()
    try:
        results = db.scalars(
            select(Memory)
            .where(Memory.namespace == namespace)
            .order_by(Memory.embedding.cosine_distance(embedding))
            .limit(top_k)
        ).all()
        return {
            "matches": [
                {"id": m.id, "content": decrypt(m.content), "agent_id": m.agent_id}
                for m in results
            ]
        }
    finally:
        db.close()


@app.delete("/memory/delete")
def delete_memory(req: DeleteRequest):
    db = SessionLocal()
    try:
        result = db.execute(delete(Memory).where(Memory.id == req.memory_id))
        db.commit()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Memory not found")
        return {"status": "deleted", "id": req.memory_id}
    finally:
        db.close()


@app.get("/")
def root():
    return {"message": "SecureMem Memory API running"}