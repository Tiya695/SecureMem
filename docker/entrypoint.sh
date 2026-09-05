#!/bin/sh
set -e

echo "Ensuring database tables exist..."
python -c "
from memory.database import engine
from memory.models import Base
Base.metadata.create_all(engine)
print('Tables ready:', list(Base.metadata.tables.keys()))
"

echo "Starting SecureMem AI..."
exec uvicorn backend.main:app --host 0.0.0.0 --port 8000
