# Oracle VM Creator

[Русский](README.ru.md) · **English**

A web wizard that walks a non-technical person through getting a free ARM VM
in Oracle Cloud: sign-up → API key → automatic network setup → hunting for free
capacity → downloading the SSH key.

Always Free limits: **2 OCPU / 12 GB** for free-tier accounts (quietly halved by
Oracle on June 15, 2026; PAYG accounts reportedly still get 4 OCPU / 24 GB free).

Supports **multiple users in parallel**: access tokens are listed comma-separated
in `ACCESS_TOKENS` (`.env`); each token gets an isolated session
(`data/sessions/<hash>/` — its own keys, state, and capacity hunt).

## How it works

1. The user opens a personal link `https://<your-domain>/?t=<token>`.
2. Step 1 — instructions for signing up for Oracle Cloud (with home region
   recommendations, since Always Free capacity varies a lot by region).
3. Step 2 — the service generates an RSA key pair; the user pastes the public part
   into the Oracle console (User settings → Tokens and keys → Add API key) and pastes
   the resulting `[DEFAULT]...` config snippet back. The service validates access
   with a live API call.
4. Step 3 — automatic setup: VCN + Internet Gateway + route + public subnet
   (or reuse of existing ones), the latest Ubuntu ARM image, an ed25519 SSH key.
5. Steps 4–5 — a background `launch_instance` loop cycling through availability
   domains (error handling: Out of capacity → retry in 60 s, 429 → 120 s,
   LimitExceeded → stop with an explanation). Hunts survive container restarts.
6. Step 6 — public IP, private SSH key download, and a button to wipe all user
   data (API key, SSH key, state).

## Deployment

```bash
# on your server
git clone https://github.com/Lexx143/oracle-vm-creator.git
cd oracle-vm-creator
echo "ACCESS_TOKENS=$(openssl rand -hex 24)" > .env   # one token per user, comma-separated
docker compose up -d --build
```

The container listens on `172.17.0.1:3002` — the docker bridge, convenient when the
reverse proxy also runs in docker (change to `127.0.0.1:3002` in `docker-compose.yml`
if your proxy runs on the host). Put any HTTPS reverse proxy in front, e.g. Caddy:

```
vm.example.com {
    reverse_proxy 172.17.0.1:3002
}
```

User link: `https://vm.example.com/?t=<token from .env>`.

## Local development

```bash
pip install -r requirements.txt
ACCESS_TOKENS=devtoken uvicorn app.main:app --reload
# http://127.0.0.1:8000/?t=devtoken
```

## Adding a new user

Append a new token to `ACCESS_TOKENS` (`.env`) and run `docker compose up -d` —
other users' active hunts resume automatically. To delete a user's data, use the
"Delete my data" button in the UI, or `rm -rf data/sessions/<hash>`
(hash = sha256(token)[:16]).

## Security

- The user's private OCI API key and SSH key live only in `data/` (gitignored).
- Access via a secret token (query parameter → httponly cookie); HTTPS is the
  reverse proxy's job.
- After downloading the SSH key, the user is prompted to wipe all their data.
- Keep in mind: the API key grants full access to the user's Oracle account — the
  service assumes trust between whoever hosts it and whoever uses it.

## Note

The wizard UI is currently in Russian.
