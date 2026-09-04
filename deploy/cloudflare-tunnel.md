# Server Setup — Ubuntu Desktop 20.04 + Cloudflare Tunnel

Full procedure for turning a fresh Ubuntu Desktop 20.04 install into an
always-on host for `rgcdoortodoorboxservices.ca`, reachable through a
Cloudflare Tunnel instead of router port-forwarding + dynamic DNS — the
setup that works under CGNAT (no public IP to point a domain at, no ports
you can forward from your router because inbound traffic never reaches it).

Compared to the plain self-hosting instructions in the project's own
`README.md`, this version **skips**: router port forwarding, `godaddy-ddns.sh`
+ its cron job, and `certbot`/Let's Encrypt. Cloudflare's edge handles public
HTTPS and DNS for you; your box only ever makes outbound connections.

Replace `<your-username>` and `192.168.1.50` below with your own login and
whatever local IP you reserve. `/opt/rgcdoortodoor` is where the project
folder ends up on the server.

---

## 1. Post-install OS prep (Ubuntu Desktop specifics)

This machine is now a server that happens to have a desktop on it — a few
defaults fight that.

**Turn off automatic suspend** — otherwise the whole machine sleeps after
inactivity and the site goes down with it:
Settings → Power → set "Screen Blank" and "Automatic Suspend" to **Off** (or
"Never").

**If it's a laptop, stop it suspending on lid close:**
```bash
sudo nano /etc/systemd/logind.conf
# set:
#   HandleLidSwitch=ignore
#   HandleLidSwitchDocked=ignore
sudo systemctl restart systemd-logind
```

**Turn off unattended-upgrade reboots** (you want to control when this
machine restarts, not have it happen mid-order):
Settings → Software Updates, or:
```bash
sudo dpkg-reconfigure unattended-upgrades
```

**Enable SSH** so you can do the rest of this from another computer instead
of sitting at the machine:
```bash
sudo apt install -y openssh-server
```
Then from another computer on the same network:
```bash
ssh <your-username>@192.168.1.50
```

**Give the machine a fixed local IP.** In your router's admin page, set a
**DHCP reservation** ("static lease") for this machine's MAC address (e.g.
`192.168.1.50`) so its local address never changes on reboot. This is
separate from — and still needed even though — you're not port-forwarding
anymore; the tunnel software needs a stable place to run, and SSH access
benefits from it too.

## 2. Update the system and install required packages

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-venv python3-pip git nginx postgresql postgresql-contrib ufw
```

Note what's **not** in this list versus the plain self-hosting guide:
`certbot` / `python3-certbot-nginx`. Cloudflare terminates public HTTPS for
you, so there's no local certificate to issue or renew.

## 3. Get the app onto the server

```bash
sudo mkdir -p /opt/rgcdoortodoor
sudo chown "$USER":"$USER" /opt/rgcdoortodoor
git clone <your-repo-url> /opt/rgcdoortodoor
```
(No git repo yet? Copy the project folder over with `scp`/`rsync` from
wherever it currently lives instead.)

Create a dedicated, unprivileged user to run the app — don't run it as root
or your login user:
```bash
sudo useradd --system --home /opt/rgcdoortodoor --shell /usr/sbin/nologin rgcapp
sudo chown -R rgcapp:rgcapp /opt/rgcdoortodoor
```

## 4. Python environment

```bash
cd /opt/rgcdoortodoor
sudo -u rgcapp python3 -m venv venv
sudo -u rgcapp ./venv/bin/pip install -r requirements.txt
```

## 5. PostgreSQL (local database)

```bash
sudo -u postgres psql -c "CREATE USER rgc WITH PASSWORD 'choose-a-strong-password';"
sudo -u postgres psql -c "CREATE DATABASE rgc OWNER rgc;"
```
Note the password — it goes into `DATABASE_URL` in the next step. Postgres
only needs to accept connections from `localhost`, which is its default.

## 6. Environment variables

```bash
cp deploy/.env.example /opt/rgcdoortodoor/.env
nano /opt/rgcdoortodoor/.env   # fill in real values
sudo chown rgcapp:rgcapp /opt/rgcdoortodoor/.env
sudo chmod 600 /opt/rgcdoortodoor/.env
```
At minimum set:
- `SECRET_KEY` — any long random string, keep it constant across restarts
  (rotating it logs everyone out — see the project README's "Staying logged
  in" section)
- `ADMIN_USERNAME` / `ADMIN_PASSWORD`
- `DATABASE_URL=postgresql://rgc:<that-password>@localhost:5432/rgc`
- `SMTP_USERNAME` / `SMTP_PASSWORD` (see the README's "Sending email via
  Microsoft 365 SMTP" section)
- `KEEP_ALIVE_ENABLED=false` (this only matters on Render's free tier)

## 7. Run the app as a systemd service

```bash
sudo cp deploy/rgc.service /etc/systemd/system/rgc.service
sudo systemctl daemon-reload
sudo systemctl enable --now rgc
sudo systemctl status rgc     # should show "active (running)"
```
This starts gunicorn on boot and restarts it automatically if it crashes.
`journalctl -u rgc -f` tails its logs. It binds to `127.0.0.1:8000` — not
reachable from outside the machine, by design; nginx is the only thing that
talks to it directly.

## 8. Nginx reverse proxy

```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/rgc
sudo ln -s /etc/nginx/sites-available/rgc /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

**Optional hardening:** since nothing outside this machine needs to reach
nginx directly anymore (the tunnel is the only path in), you can bind it to
loopback only. Edit `/etc/nginx/sites-available/rgc` and change:
```
listen 80;
listen [::]:80;
```
to:
```
listen 127.0.0.1:80;
```
then `sudo nginx -t && sudo systemctl reload nginx` again. Skip this if
you're not sure — the firewall step below already blocks outside access to
port 80 either way.

No certbot step here — nginx stays plain HTTP, because the only client
talking to it from now on is `cloudflared`, running on the same machine.

## 9. Firewall

```bash
sudo ufw allow OpenSSH
sudo ufw enable
```
Note this is shorter than the plain self-hosting guide: **don't** add
`sudo ufw allow 'Nginx Full'`. Port 80/443 never need to accept connections
from outside this machine — the tunnel carries traffic in over an outbound
connection instead, so there's nothing to open for it.

## 10. Move the domain's DNS to Cloudflare

1. Sign up at [cloudflare.com](https://cloudflare.com) (free plan) and "Add
   a site" for `rgcdoortodoorboxservices.ca`. It scans your existing GoDaddy
   DNS records and shows two nameservers to switch to.
2. In GoDaddy: your domain → **Nameservers** → change from GoDaddy's default
   to the two Cloudflare nameservers it gave you.
3. Wait for the switch to take effect (usually well under an hour;
   Cloudflare's dashboard shows "Active" once it's done). The domain stays
   registered at GoDaddy — only DNS management moves to Cloudflare.

## 11. Install and configure cloudflared

```bash
curl -L https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt update && sudo apt install cloudflared
```

Authenticate (opens a browser — pick `rgcdoortodoorboxservices.ca` when
prompted):
```bash
cloudflared tunnel login
```

Create the tunnel:
```bash
cloudflared tunnel create rgc
```
This prints a tunnel ID and writes credentials to
`~/.cloudflared/<tunnel-id>.json` — note the ID for the config file below.

Create `~/.cloudflared/config.yml`:
```yaml
tunnel: <tunnel-id>
credentials-file: /home/<your-username>/.cloudflared/<tunnel-id>.json

ingress:
  - hostname: rgcdoortodoorboxservices.ca
    service: http://localhost:80
  - hostname: www.rgcdoortodoorboxservices.ca
    service: http://localhost:80
  - service: http_status:404
```
Point at nginx on `localhost:80`, not straight at gunicorn on `8000` —
nginx still handles `/static/` directly and this keeps that behavior. The
`http_status:404` line must be last; it's required as the catch-all.

Route the domain to the tunnel (creates the DNS records in Cloudflare
automatically):
```bash
cloudflared tunnel route dns rgc rgcdoortodoorboxservices.ca
cloudflared tunnel route dns rgc www.rgcdoortodoorboxservices.ca
```

Install and start it as a service so it survives reboots:
```bash
sudo cloudflared service install
sudo systemctl enable --now cloudflared
sudo systemctl status cloudflared    # should show "active (running)"
```

## 12. Verify end to end

- `sudo systemctl status rgc nginx cloudflared` — all three should be
  `active (running)`.
- Visit `https://rgcdoortodoorboxservices.ca` from a phone on cellular data
  (not your home Wi-Fi, so you're actually testing the public path) — should
  load over HTTPS with a valid certificate, issued by Cloudflare.
- Check the padlock/cert details: it'll show a Cloudflare-issued cert, not
  Let's Encrypt — that's expected and correct for this setup.
- `journalctl -u cloudflared -f` if the site doesn't load — shows tunnel
  connection status and errors.

## 13. Backups

```bash
chmod +x deploy/backup.sh
sudo -u rgcapp crontab -e
# add:
0 3 * * * /opt/rgcdoortodoor/deploy/backup.sh >> /var/log/rgc-backup.log 2>&1
```
Needs a `~/.pgpass` entry for the `rgcapp` user so `pg_dump` doesn't need a
password on the command line — one line in `/home/rgcapp/.pgpass`:
```
localhost:5432:rgc:rgc:<your-db-password>
```
then `chmod 600 /home/rgcapp/.pgpass` (as the `rgcapp` user, or
`sudo -u rgcapp` it).

This dumps the database and archives uploaded images nightly, keeping 14
days locally. For protection against the machine itself failing (drive
failure, fire, theft), copy the newest backups off-machine periodically too
— see the comment at the bottom of `backup.sh` for an `rclone` example.

## 14. Updating the app later

```bash
cd /opt/rgcdoortodoor
sudo -u rgcapp git pull
sudo -u rgcapp ./venv/bin/pip install -r requirements.txt
sudo systemctl restart rgc
```
Nothing to do for `cloudflared` or nginx on a normal app update — only
restart `rgc` unless you changed `nginx.conf` or `config.yml` themselves.

## 15. Things worth testing once, up front

- **Outbound SMTP (port 587).** Some residential ISPs block outbound mail
  ports to cut down on spam from home connections. Confirm the contact form
  and order-confirmation emails actually send once you're live — if they
  silently fail, check whether your ISP blocks 587/25 before assuming it's a
  code or credentials problem.
- **Cloudflare SSL/TLS mode.** In the Cloudflare dashboard → SSL/TLS, use
  **Flexible** (Cloudflare↔visitor is HTTPS, Cloudflare↔your tunnel is
  plain HTTP — which matches this guide's plain-HTTP nginx). If you'd rather
  encrypt the Cloudflare↔tunnel leg too, that needs an origin certificate
  and nginx changes not covered here — Flexible is fine for this setup since
  the tunnel itself is already an encrypted, authenticated channel, not
  plain internet-facing HTTP.

---

### Quick reference — what replaced what

| Plain self-hosting guide | This guide |
|---|---|
| Router port-forward 80/443 | Not needed — `cloudflared` is outbound-only |
| `deploy/godaddy-ddns.sh` + cron | Not needed — tunnel doesn't care about your IP |
| `certbot --nginx ...` | Not needed — Cloudflare issues the public cert |
| `ufw allow 'Nginx Full'` | Skipped — port 80 never needs to be open externally |
| A record at GoDaddy | Nameservers moved to Cloudflare; CNAME added by `cloudflared tunnel route dns` |
