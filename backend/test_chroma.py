import chromadb
from sentence_transformers import SentenceTransformer

# Set up embedding model
model = SentenceTransformer('all-MiniLM-L6-v2')

# Set up ChromaDB (stores data locally in a folder called "chroma_data")
client = chromadb.PersistentClient(path="chroma_data")
collection = client.get_or_create_collection(name="memories")

# Some sample "memories" to store
memories = [
    "User prefers vegetarian food",
    "User is planning a trip to the mountains next month",
    "User's favorite color is blue",
    "User wants to save money for a new laptop"
]

# Convert each memory to an embedding and add to the collection
for i, memory in enumerate(memories):
    embedding = model.encode(memory).tolist()
    collection.add(
        ids=[f"mem_{i}"],
        embeddings=[embedding],
        documents=[memory]
    )

print("Stored", len(memories), "memories.")

# Now search: find memories related to a new query
query = "What outdoor activities does the user like?"
query_embedding = model.encode(query).tolist()

results = collection.query(
    query_embeddings=[query_embedding],
    n_results=2
)

print("\nQuery:", query)
print("Top matches:")
for doc in results['documents'][0]:
    print(" -", doc)