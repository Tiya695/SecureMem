from fastapi import FastAPI
from pydantic import BaseModel
import chromadb
from sentence_transformers import SentenceTransformer

app = FastAPI()

model = SentenceTransformer('all-MiniLM-L6-v2')
client = chromadb.PersistentClient(path="chroma_data")
collection = client.get_or_create_collection(name="memories")

class Memory(BaseModel):
    text: str

class Query(BaseModel):
    text: str
    n_results: int = 2

@app.post("/add_memory")
def add_memory(memory: Memory):
    count = collection.count()
    embedding = model.encode(memory.text).tolist()
    collection.add(
        ids=[f"mem_{count}"],
        embeddings=[embedding],
        documents=[memory.text]
    )
    return {"status": "stored", "id": f"mem_{count}"}

@app.post("/search_memory")
def search_memory(query: Query):
    embedding = model.encode(query.text).tolist()
    results = collection.query(
        query_embeddings=[embedding],
        n_results=query.n_results
    )
    return {"matches": results['documents'][0]}

@app.get("/")
def root():
    return {"message": "SecureMem backend is running"}