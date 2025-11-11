# WealthSense — Mini AI-Powered Stock Portfolio Advisor

A small, fast, and presentation-ready demo built with FastAPI + Mongo (server) and Vite + React (client). Dark, modern UI with responsive design and a clean flow.

Note: You requested Flask + SQLite, but this environment ships with FastAPI + Mongo pre-configured. The app is implemented with FastAPI while honoring your UX and logic requirements.

## Features
- Landing page with 3D fintech hero
- Sign Up with PAN, phone, email validation (pending by default)
- Broker view to activate users and generate unique IDs like WSN-1001
- Sign In with first-time password setup and returning login
- Dashboard to view/add holdings, quick portfolio checkup, finance quick tips (AI if key set), and export CSV

## Quick Start

1. Install and run (handled automatically in this environment). For local use:
   - Backend
     - python -m venv .venv && source .venv/bin/activate
     - pip install -r requirements.txt
     - export BROKER_PASSWORD=broker123
     - export OPENAI_API_KEY=your_key_optional
     - uvicorn main:app --reload --port 8000
   - Frontend
     - npm install
     - export VITE_BACKEND_URL=http://localhost:8000
     - npm run dev

2. Visit the frontend on http://localhost:3000

3. Optional: Create a .env file with:
```
BROKER_PASSWORD=broker123
OPENAI_API_KEY=
```

## Sample Data
- A demo active user is seeded: unique_id WSN-1000, password demo1234, with two sample holdings.

## Notes
- PAN validated as 5 letters + 4 digits + 1 letter
- Passwords hashed with Werkzeug
- If OPENAI_API_KEY is missing, tips fall back to a static list
