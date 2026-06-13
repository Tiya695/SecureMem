\# SecureMem AI — Architecture Overview



\## Flow



Agent (sends request)

&#x20;  |

&#x20;  v

Memory API (FastAPI)

&#x20;  |

&#x20;  v

Embedding Model (sentence-transformers, converts text -> 384/1536 numbers)

&#x20;  |

&#x20;  v

Vector Database (pgvector / PostgreSQL)

&#x20;  |

&#x20;  v

Returns relevant memories (ranked by similarity) -> back to Agent



\## Why pgvector over Pinecone?



\- pgvector is free and runs locally (Pinecone is a paid cloud service)

\- We already use PostgreSQL, so no extra infrastructure needed

\- Good enough performance for our project's scale (student project, not millions of vectors)

\- Full control over data (important for a "secure" memory system)



\## Key Concepts



\- \*\*Embedding\*\*: text converted into a list of numbers representing meaning

\- \*\*Cosine similarity\*\*: measures how close two embeddings are (used for semantic search)

\- \*\*Namespace\*\*: separates memories belonging to different agents (for RBAC/isolation)

