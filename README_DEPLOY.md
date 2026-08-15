# EAII Security Platform — Vercel Deployment

## Structure
- `api/index.py` — Flask application
- `vercel.json` — Vercel routing; no invalid runtime declaration
- `requirements.txt` — Python dependencies
- `logo.png` — header/report brand asset

## Deploy
1. Commit and push these files to GitHub.
2. Vercel imports the repository.
3. Redeploy the `main` branch.
4. Add `SECRET_KEY` in Vercel Environment Variables.
5. Open the deployment URL.

## Notes
Vercel automatically detects Python functions under `/api`; the configuration intentionally does not specify `python3.9` or `python@3.9`.
The SQLite database remains `/tmp/security_assessment.db`, so it is ephemeral on Vercel.
The report includes a `Print / Save PDF` action using the browser print dialog and keeps the existing HTML download route.
