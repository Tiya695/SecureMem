from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

model = SentenceTransformer('all-MiniLM-L6-v2')

sentences = [
    "I love hiking in the mountains",
    "I enjoy trekking on hills",
    "I want to order pizza for dinner"
]

embeddings = model.encode(sentences)

print("Similarity (hiking vs trekking):", cosine_similarity([embeddings[0]], [embeddings[1]])[0][0])
print("Similarity (hiking vs pizza):", cosine_similarity([embeddings[0]], [embeddings[2]])[0][0])