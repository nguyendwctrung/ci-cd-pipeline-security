# Security Pipeline Dashboard

Standalone Streamlit monitoring for `security_system`. It does not depend on PokeMap or Node.js.

## Components

- `backend`: FastAPI endpoint for signed GitHub Actions ingestion
- `dashboard`: password-protected Streamlit dashboard
- MongoDB Atlas: dedicated 90-day sanitized monitoring history

Raw scanner reports, source snippets, secrets, and Gemini prompts remain in protected GitHub Actions artifacts.

## Local setup

1. In MongoDB Atlas, create a database user with access to the monitoring database.
2. In Atlas Network Access, allow the public IP addresses of the deployed FastAPI and Streamlit services.
3. Open Atlas **Connect > Drivers** and copy the Python connection string.
4. URL-encode special characters in the database username or password before inserting them into the URI.
5. Copy `backend/.env.example` to `backend/.env` and insert the Atlas URI.
6. Copy `dashboard/.streamlit/secrets.toml.example` to `dashboard/.streamlit/secrets.toml` and insert the same Atlas URI and database name.
7. Generate a password hash:

```powershell
Set-Location security_dashboard/dashboard
python -c "from auth import hash_password; import getpass; print(hash_password(getpass.getpass('Dashboard password: ')))"
```

8. Put the generated value in `dashboard_password_hash` inside `secrets.toml`.
9. Start the services:

```bash
docker compose up --build
```

Open the dashboard at `http://localhost:8501`. The ingestion health endpoint is available at `http://localhost:8001/health`.

## GitHub configuration

Configure these repository secrets:

- `SECURITY_MONITOR_URL`, for example `https://monitor-api.example.com`
- `SECURITY_MONITOR_SECRET`, matching `backend/.env`

GitHub Actions sends `monitor_report.json` only to FastAPI. Streamlit reads sanitized history directly from MongoDB. Monitoring publication is non-blocking and never changes the security gate result.

The repository does not start a local MongoDB container. Both services fail clearly when their Atlas configuration is missing. Never commit `backend/.env` or `dashboard/.streamlit/secrets.toml`.
