# flask-project-2

## Deployment
Ready for any Python PaaS (Render, Railway, Heroku, Fly.io, etc).

- Procfile included for gunicorn.
- Set environment variables: `SECRET_KEY`, `MAIL_USERNAME`, `MAIL_PASSWORD` (Gmail app password recommended).
- Database uses portable `instance/notes.db` (note: ephemeral storage on most free tiers - data lost on redeploy unless you attach persistent disk/volume).
- Password reset emails are optional; if mail not configured, reset links are printed to server logs instead of crashing.
- To run locally: `flask run` or `python app.py` (after setting env vars and `pip install -r requirements.txt`).

For production, disable debug (default now) and use proper SECRET_KEY.