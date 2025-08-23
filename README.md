# Telegram Link Changer Bot (Link Provider Bot)

A production-ready, modular Telegram bot using **Pyrogram** that generates **temporary links (10s expiry)** for channels and external URLs, manages channel join requests with optional auto-approval, and includes a full admin toolkit.

## Features
- `/start` sends a welcome photo + inline buttons (**About / Update / Help**) and checks bot alive.
- **Temporary links** (10 seconds): for channels and external links using signed tokens.
- Admin commands to add/remove/list channels.
- Request system: auto-approval mode + timer; approve on/off per-channel; approve all.
- Owner/Admin utilities: stats, status, broadcast.
- SQLite (default) or any SQL via `DATABASE_URL`.
- Deploy on **Heroku**, **Render**, or **Docker**.

## Environment Variables
Create a `.env` file (or set via host env):
```ini
API_ID=12345
API_HASH=your_api_hash
BOT_TOKEN=12345:abc_bot_token
OWNER_IDS=123456789,987654321        # comma-separated Telegram user IDs
DATABASE_URL=sqlite+sqlite:///data.db # default auto-fallback to ./data.db
START_IMAGE=https://example.com/welcome.jpg
ABOUT_TEXT=This is a Link Provider Bot.
UPDATES_TEXT=Latest updates here.
HELP_TEXT=Use /reqlink, /links, /genlink, /bulklink etc.
REQUEST_MODE=off                     # on/off
REQUEST_TIMER=10                     # seconds for auto-approval delay
SECRET_KEY=change_me                 # used to sign tokens
```

## Quick Start (local)
```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python main.py
```

## Heroku (Procfile provided)
```bash
heroku create
heroku config:set API_ID=... API_HASH=... BOT_TOKEN=... OWNER_IDS=... SECRET_KEY=...
git push heroku main
```

## Render
Use `render.yaml` and fill environment variables in dashboard.

## Docker
```bash
docker build -t link-provider-bot .
docker run --env-file .env link-provider-bot
```

## Notes
- Bot must be **admin** in target channels to receive/judge join requests.
- Temporary links are served as deep-links to the bot (`/start token`) that resolve to either an external URL redirect message or a channel invite processing step. Expire after 10 seconds.
- "Approve all" works on requests observed while bot is running.
```

