# Web Companion: backend

Accounts, sign-in and per-user data. Deploy as a Render Web Service, separate from the frontend.

1. Create a Postgres database (Neon or Render) and copy its connection string.
2. Push this folder to GitHub. In Render: New > Blueprint (uses render.yaml) or New > Web Service with build command `npm install` and start command `npm start`.
3. Set environment variables: DATABASE_URL, FRONTEND_ORIGIN (your frontend address, no trailing slash), PGSSL=require.
4. Check https://<your-api>/api/health. It should return {"ok":true}.

## Self-healing built in
- Startup retries the database up to 10 times with backoff, then exits so Render restarts the service.
- Dropped database connections are replaced automatically and logged.
- Every 60 seconds the server checks the database. Every 10 minutes it re-creates any missing tables.
- Database outages return 503 with Retry-After, so the frontend waits and retries instead of failing.
- Uncaught errors are logged and the process restarts cleanly under Render's supervisor.
- The health check path (/api/health) lets Render restart the service if it stops responding.

## Limits
- This cannot fix every problem automatically. Bugs in code, a deleted database, or a wrong password need a person to act. Check the Render logs.
- Free Render services sleep when idle, and free Postgres has no backups.
- Sign-in limits (20 attempts per 15 minutes per IP) reset when the server restarts.
- No password reset yet. That needs an HTTPS email provider.
