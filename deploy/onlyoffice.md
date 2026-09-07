# OnlyOffice Document Server — real in-browser Word/Excel editing

This is what powers the "Edit Online" button in Admin > Documents (see the
`ONLYOFFICE_URL`/`ONLYOFFICE_JWT_SECRET` comment above `ONLYOFFICE_URL` in
`app.py`). It's a separate, open-source (AGPLv3) service — OnlyOffice
Document Server — that does the actual document rendering/editing; this
Flask app just embeds its editor and exchanges files with it. Nothing about
Documents (upload, preview, download, editing details) requires this —
skip this whole guide if the read-only preview + re-upload workflow is
enough for you.

Written to slot into the Ubuntu + Cloudflare Tunnel setup from
`deploy/cloudflare-tunnel.md`. If you're self-hosting differently, the
Flask-side pieces (env vars, the callback route) stay the same — only the
container networking / tunnel steps below need adapting.

## 1. Install Docker

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
```
Log out and back in (or `newgrp docker`) for the group change to take
effect, then confirm with `docker run hello-world`.

## 2. Generate a JWT secret

This is the shared password between this app and the document server — it
proves a request to load a document, or a save-callback, actually came from
your document server and not from a random visitor who found the URL.

```bash
openssl rand -hex 32
```
Save this value — it goes into **both** `ONLYOFFICE_JWT_SECRET` (this app's
`.env`, step 5) and the container's `JWT_SECRET` (step 3) below. They must
match exactly.

## 3. Run the Document Server container

```bash
sudo docker run -d \
  --name onlyoffice-documentserver \
  --restart unless-stopped \
  -p 127.0.0.1:8082:80 \
  -e JWT_ENABLED=true \
  -e JWT_SECRET='<the value from step 2>' \
  -e JWT_HEADER=Authorization \
  -v onlyoffice_data:/var/www/onlyoffice/Data \
  -v onlyoffice_log:/var/log/onlyoffice \
  onlyoffice/documentserver:latest
```
`-p 127.0.0.1:8082:80` binds it to **loopback only** — it's never directly
reachable from the internet, same reasoning as gunicorn binding to
`127.0.0.1:8000` in `deploy/rgc.service`. The Cloudflare Tunnel (step 4) is
the only path in from outside this machine, and this app talks to it over
loopback too (via `ONLYOFFICE_URL`, step 5).

It needs roughly 1–2 GB RAM free and takes a minute or two to finish
starting up the first time. Check with:
```bash
sudo docker logs -f onlyoffice-documentserver
```
It's ready once the logs settle down and
`curl http://127.0.0.1:8082/healthcheck` returns `true`.

## 4. Expose it through the existing Cloudflare Tunnel

Pick a subdomain (this guide uses `office.rgcdoortodoorboxservices.ca`).
Add it to the tunnel's ingress list in `~/.cloudflared/config.yml`
alongside the existing entries from `deploy/cloudflare-tunnel.md` — **it
must come before** the `http_status:404` catch-all line:

```yaml
tunnel: <tunnel-id>
credentials-file: /home/<your-username>/.cloudflared/<tunnel-id>.json

ingress:
  - hostname: rgcdoortodoorboxservices.ca
    service: http://localhost:80
  - hostname: www.rgcdoortodoorboxservices.ca
    service: http://localhost:80
  - hostname: office.rgcdoortodoorboxservices.ca
    service: http://localhost:8082
  - service: http_status:404
```
This routes the new subdomain straight to the container, bypassing nginx —
there's no `/static/` special-casing needed for it like there is for the
main site.

Route the DNS record and restart the tunnel:
```bash
cloudflared tunnel route dns rgc office.rgcdoortodoorboxservices.ca
sudo systemctl restart cloudflared
```

Verify: `https://office.rgcdoortodoorboxservices.ca/healthcheck` should
return `true` in a browser.

## 5. Configure this app

Add to `/opt/rgcdoortodoor/.env` (see `deploy/.env.example`):
```
ONLYOFFICE_URL=https://office.rgcdoortodoorboxservices.ca
ONLYOFFICE_JWT_SECRET=<the same value from step 2>
```
Then:
```bash
sudo systemctl restart rgc
```

## 6. Try it

Admin > Documents > upload a `.docx` or `.xlsx` > "Edit Online" should now
open OnlyOffice's editor right on the page. Type something, wait a few
seconds (or close the tab), then re-open the document — your change should
be there. If it isn't:

- `sudo docker logs onlyoffice-documentserver` — look for JWT/signature
  errors, which almost always mean the secret in step 2 doesn't match
  between `.env` and the container.
- `journalctl -u rgc -f` while saving — this app logs nothing extra on
  purpose (Flask's own request log line for
  `/admin/documents/<id>/onlyoffice-callback` shows whether the document
  server ever called back at all, and with what status code).
- Confirm the document server can reach this app's own public URL — it
  fetches the source file from `https://rgcdoortodoorboxservices.ca/static/
  documents/...` (same public static file serving Products/Updates photos
  already use), so if outbound access from the container is somehow
  restricted, that fetch fails silently on OnlyOffice's side.

## 7. Updating later

```bash
sudo docker pull onlyoffice/documentserver:latest
sudo docker stop onlyoffice-documentserver
sudo docker rm onlyoffice-documentserver
# then re-run the `docker run ...` command from step 3 — the named
# volumes (onlyoffice_data / onlyoffice_log) keep its data across this.
```

## Turning it off

Leave `ONLYOFFICE_URL`/`ONLYOFFICE_JWT_SECRET` blank (or remove them) in
`.env` and restart `rgc` — the "Edit Online" button disappears and
Documents falls back to upload/preview/download only. The container itself
can stay stopped (`sudo docker stop onlyoffice-documentserver`) without
affecting anything else on the site.
