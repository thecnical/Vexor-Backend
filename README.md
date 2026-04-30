# Vexor Backend

> **Private Repository** — AI Router + Auth API for Vexor CLI

FastAPI backend that handles all AI provider calls so users never need API keys.

## Stack

- FastAPI + uvicorn
- SQLite (aiosqlite)
- JWT auth (python-jose)
- AI: Groq → NVIDIA NIM → OpenRouter → HuggingFace

## Deploy on Render

See [RENDER_DEPLOY.md](../docs/RENDER_DEPLOY.md)

**Environment Variables required:**
```
SECRET_KEY
GROQ_API_KEY
NVIDIA_API_KEY
OPENROUTER_API_KEY
HUGGINGFACE_API_KEY
```

## Local Dev

```bash
cp .env.example .env
# Fill in your API keys in .env

pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Docker

```bash
docker-compose up
```

---

*Created by Chandan Pandey (Technical)*
