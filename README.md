
# College Notes Hub

College Notes Hub is a responsive HTML/CSS/TypeScript frontend backed by FastAPI. It supports JWT authentication, PDF upload/download, searchable approved notes, bookmarks, personal uploads, profile updates, dashboard counts, and administrator moderation.

## Architecture

`Vite TypeScript frontend → FastAPI REST API → PostgreSQL (or local SQLite) + Supabase Storage (or local development storage)`.

The backend owns credentials, validates all requests, hashes passwords, and applies ownership/role checks. Local SQLite and `backend/uploads/` are an explicitly labeled development fallback when Supabase/production database configuration is unavailable.

## Run locally

1. Backend: `cd backend`, copy `.env.example` to `.env`, then run `python -m venv .venv`, `.\.venv\Scripts\activate`, `pip install -r requirements.txt`, and `uvicorn app.main:app --reload --port 8000`.
2. Frontend: `cd frontend`, copy `.env.example` to `.env`, run `npm install`, then `npm run dev`.
3. Open `http://localhost:5173`; Swagger is at `http://localhost:8000/docs`.

For PostgreSQL, set `DATABASE_URL` to its SQLAlchemy connection URL and initialize with `database/schema.sql` (or let SQLAlchemy create the schema). For Supabase, provide the three `SUPABASE_*` values; production deployments should make the bucket private and use signed URLs. No secrets are committed.

## Demo workflow

Register a student account, upload a valid PDF, provision an admin by setting `ADMIN_EMAIL` before its registration, approve its pending note via `/docs`, then browse, save, and download it. Admin APIs: `GET /api/admin/stats`, `GET /api/admin/notes`, and `PATCH /api/admin/notes/{id}/status`.

## Limitations

The deadline-oriented MVP persists files locally when Supabase credentials are absent and switches to private Supabase Storage with 60-second signed download URLs when configured. There is no email verification, password reset, rate limiter, or embedded preview pane; browsers preview downloaded PDFs normally. See `backend/.env.example` for all required production settings.

# College-Note-Uploading-webapp

