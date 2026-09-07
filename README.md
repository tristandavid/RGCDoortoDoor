# RGC Door-to-Door Box Express Services (Flask Recreation)

A Flask recreation of the RGC Door-to-Door Box Express Services website
(rgcdoortodoorboxservices.ca), a Stouffville, Ontario-based parcel/balikbayan
box shipping business serving the Philippines.

This is an independent, unofficial recreation built for demonstration
purposes. Content (rates, box dimensions) is illustrative — replace with the
real business's current data before using this for anything official.

## Local setup

```bash
python -m venv venv
source venv/bin/activate   # on Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open http://localhost:5000. With no `DATABASE_URL` set, the app falls
back to a local SQLite file (`rgc.db`) right next to `app.py`. Image uploads
(post photos, product photos, the site favicon) always work out of the box —
they're saved straight to this app's own `static/` folder, no cloud storage
account needed. See "Self-hosting on your own Ubuntu server" below for
running this for real without paying for Render, Supabase, or Cloudflare.

## Owner admin panel

The owner can manage everything below without touching any code, at
`/admin/login` (default username `admin`, default password `changeme123` —
**change both**, see Environment variables below). Logging in keeps the
owner signed in **site-wide, for 30 days** — no need to log in again while
browsing or managing the site; see "Staying logged in" below for the one
setting this depends on.

1. **Updates / announcements** (shown in the nav as "RGC Blog") — news,
   promos, holiday deadlines, etc. Shown on the public `/updates` page and
   the homepage.
2. **Mailbox** — a read-only view of everything sent to the business inbox
   (`info@rgcdoortodoorboxservices.ca`), right from the admin panel — see
   "Admin Mailbox" below for full details and setup.
3. **Products** — post packaging items, empty boxes, and Sari-Sari items for
   sale, each with a name, description, price (or leave it blank to show
   "Contact for pricing"), a photo, and an Available/Hidden toggle. These
   show on the public `/packaging-items`, `/empty-box-sales`, and
   `/sari-sari` pages; until the owner adds any in a given category, that
   page shows its original generic example content instead of an empty
   section. Priced, available products get an "Add to Cart" button; unpriced
   ones get a "Contact Us" button instead (see "Checkout" below).
4. **Orders** (`/admin/orders`) — every order placed through checkout: items,
   total, customer contact info, and a status you set by hand (Awaiting
   Payment / Paid / Fulfilled / Cancelled) once you confirm the Interac
   e-Transfer landed. See "Checkout & Orders" below.
5. **Subscribers** (`/admin/subscribers`) — everyone who's signed up via the
   footer's "Subscribe" box (name, email, address, and phone — only email is
   required), with a "Remove" button per person and a "Export CSV" button.
   This app doesn't send newsletters itself — export the list and paste it
   into whatever you actually send campaigns from.
6. **Pages** (`/admin/pages`) — edit the plain-text body of Privacy Policy,
   Terms and Conditions, and the intro paragraph on Contact Us, without
   touching code. About Us isn't editable here — its timeline and feature
   cards are a hand-built layout, not a simple text block.
7. **Site Settings** — upload a custom website icon (favicon), the small
   icon shown in the browser tab. Until one is uploaded, the site uses a
   default 📦 icon.

**Note on package tracking:** the public `/track` page and its underlying
data (`Shipment`/`TrackingEvent`) still exist, but the admin pages to create
shipments or post status updates have been removed — there's currently no
way to add or update tracking numbers except directly in the database.

## Staying logged in

The admin login uses a signed cookie stored in your browser, not a
database-backed account — that's normal for a single-owner site like this
and needs no extra setup. Two things make it work the way you'd expect:

1. **It's set to last 30 days** (`PERMANENT_SESSION_LIFETIME` in `app.py`),
   and applies across every page — once logged in at `/admin/login`, the
   cookie goes with you site-wide (public pages and every `/admin/...` page)
   until it expires or you hit "Log Out".
2. **`SECRET_KEY` must stay the same** across restarts and deploys. The
   cookie is cryptographically signed with it — if `SECRET_KEY` changes
   (e.g. you forgot to set it and the platform assigns a new one on every
   redeploy, or you rotate it), every existing login is invalidated and
   you'll be asked to sign in again. Set it once as an environment variable
   and leave it alone.

Want to stay logged in even longer, or on multiple devices at once? Both
already work as-is — the 30-day window covers any number of browsers/devices
simultaneously, and you can bump the `timedelta(days=30)` in `app.py` to a
larger number if you'd like a longer window.

## Environment variables

| Variable | Required? | Purpose |
|---|---|---|
| `SECRET_KEY` | Yes (prod) | Signs session cookies. Any long random string — set once, keep it constant (see "Staying logged in" above). |
| `ADMIN_USERNAME` | Recommended | Username for `/admin/login`. Defaults to `admin`. |
| `ADMIN_PASSWORD` | Yes (prod) | Password for `/admin/login`. Defaults to `changeme123` — the app prints a warning on startup if you haven't changed it. |
| `ADMIN2_USERNAME` / `ADMIN2_PASSWORD` | Optional | A second, separate admin login with the SAME full access as the owner login above (Orders/Invoices/Mailbox/Pickups/Subscribers/Users/everything) — for a co-owner or manager. Doesn't exist unless BOTH are set — leave both blank to skip it. Two-factor authentication (below) is independent per account. |
| `CREATOR_USERNAME` / `CREATOR_PASSWORD` | Optional | A third, separate admin login (e.g. for whoever maintains the site) with access to Updates/Products/Pages/Settings but NOT Orders/Invoices/Mailbox/Pickups/Subscribers. Doesn't exist unless BOTH are set — leave both blank to skip it. Two-factor authentication (below) is independent per account. |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Optional | Enables the "Sign in with Google" button on the customer portal login page. From a Google Cloud Console OAuth client (type "Web application") with `<your site>/customer/login/google/callback` authorized as a redirect URI. Doesn't exist unless BOTH are set — leave both blank to skip it. See the comment above `GOOGLE_CLIENT_ID` in `app.py`. |
| `ONLYOFFICE_URL` / `ONLYOFFICE_JWT_SECRET` | Optional | Enables the "Edit Online" button in Admin > Documents — real in-browser Word/Excel editing via a self-hosted OnlyOffice Document Server. Doesn't exist unless BOTH are set — leave both blank to skip it; Documents still works for upload/preview/download without it. See `deploy/onlyoffice.md`. |
| `DATABASE_URL` | Recommended | Postgres connection string, e.g. `postgresql://rgc:password@localhost:5432/rgc` for a self-hosted Postgres (see below), or whatever a managed provider gives you. Without it, falls back to local SQLite. |
| `SMTP_USERNAME` | For contact-form emails | The mailbox's sign-in address. Defaults to `COMPANY["contact_email"]` in `app.py` (`info@rgcdoortodoorboxservices.ca`). |
| `SMTP_PASSWORD` | For contact-form emails | That mailbox's sign-in password. |
| `SMTP_HOST` | Optional | Defaults to `smtp.office365.com`. Only change this if you switch mailbox providers. |
| `SMTP_PORT` | Optional | Defaults to `587`. |
| `CONTACT_RECIPIENT_EMAIL` | Optional | Where contact-form messages are sent. Defaults to `COMPANY["contact_email"]` in `app.py`. |
| `KEEP_ALIVE_ENABLED` | Optional | Set to `false` to turn off the free-tier keep-alive (see below). Defaults on whenever `RENDER_EXTERNAL_URL` exists. |
| `KEEP_ALIVE_INTERVAL_SECONDS` | Optional | How often the keep-alive pings itself. Defaults to `600` (10 minutes). |
| `MOBILE_TOKEN_MAX_AGE_DAYS` | Optional | How many days an RGC Manager Android app login token stays valid before that phone needs to sign in again. Defaults to `180`. See "Mobile API" below. |

If `SMTP_PASSWORD` isn't set, the contact form still shows its normal
confirmation message, it just doesn't email anything anywhere — handy for
local dev, but set it before relying on it in production.

### Sending email via Microsoft 365 SMTP

Contact-form, pickup-request, order, and admin-Mailbox-reply emails are sent
by authenticating directly as `info@rgcdoortodoorboxservices.ca` over SMTP —
the same mailbox used for reading and replying by hand, so sending and
receiving both live on Microsoft 365, no third party involved.

(This app briefly used Mailgun's HTTP API instead, to work around Microsoft's
ongoing phase-out of SMTP AUTH. That Mailgun account hit an unresolved
account-level authentication error that Mailgun support couldn't explain from
the dashboard, so this reverted back to direct SMTP. Basic Auth for SMTP was
confirmed still enabled on this tenant before reverting — worth re-testing if
you ever hit send failures, since Microsoft could disable it tenant-wide at
any time with no warning.)

1. **Set the environment variables** (in `deploy/.env` on the server, or
   locally in a `.env`/your shell for dev): `SMTP_USERNAME` (defaults to
   `info@rgcdoortodoorboxservices.ca`) and `SMTP_PASSWORD` (the mailbox's
   own sign-in password).
2. That's it — `SMTP_HOST` (`smtp.office365.com`) and `SMTP_PORT` (`587`)
   already default correctly for Microsoft 365 and don't need to be set
   unless you switch mailbox providers later.
3. **Restart the service** after changing `deploy/.env` on the server —
   systemd only reads `EnvironmentFile=` at start, not on save:
   `sudo systemctl restart rgc`.

### Admin Mailbox

`/admin/mailbox` shows contact-form and pickup-request submissions, plus any
reply/compose sent from here — right from the admin panel. It does **not**
mirror everything else sent to the real mailbox; use your real mailbox
(Outlook) to see and respond to anything that didn't come through the
website's own forms.

**Why it doesn't mirror everything:** Microsoft 365 from GoDaddy manages your
tenant through GoDaddy's own simplified dashboard, which doesn't expose
Microsoft Entra ID (Azure AD) — so registering an app with Microsoft Graph
permissions (the normal way to read real mailbox content) isn't available
here. Separately, IMAP with a plain username/password has been fully disabled
by Microsoft for every tenant since 2023, with no way to re-enable it. A full
live mirror would need a third-party inbound-email relay (this app used
Mailgun for that at one point) parsing incoming mail and posting it to this
app — currently not in use, so `/admin/mailbox` only ever shows what's saved
directly by the app itself (`contact_us()` and `_send_mailbox_reply()` in
`app.py`).



### Checkout & Orders

Customers can add priced, available Products to a cart (`/cart`, stored in
their browser session — no account needed) and check out (`/checkout`),
paying by **Interac e-Transfer**.

**Why e-Transfer works this way:** Interac doesn't offer a public API a
small merchant can integrate with to verify a payment lands in real time —
that kind of instant confirmation is a Stripe/PayPal thing, not an Interac
thing. So checkout here works like most small Canadian businesses handle it
manually:

1. The customer fills in their name, email, phone (optional), and shipping/
   pickup notes, and places the order.
2. An order is created with status **Awaiting Payment**, and two emails go
   out through the same SMTP send the contact form uses: one to you
   (`CONTACT_RECIPIENT_EMAIL`) with the order details, one to the customer
   with a summary and payment instructions — send an e-Transfer for the
   order total to `CONTACT_RECIPIENT_EMAIL`, with the order number
   (e.g. `ORD-A1B2C3D4`) in the e-Transfer's message/memo field.
3. The customer also sees those same instructions right away on the
   order-confirmation page, and can return to it later at
   `/order-confirmation/<order number>`.
4. **You check your online banking** for the incoming e-Transfer, matching
   it to the order by the amount and the order number in the memo. Once
   confirmed, go to `/admin/orders` → open that order → change its status
   to **Paid**, then **Fulfilled** once it's shipped/picked up.

If a customer's Interac account requires answering a security question
(rather than Autodeposit), the instructions ask them to contact you for the
answer — set up Autodeposit on your Interac-enabled account if you'd rather
skip that step entirely for every order.

Order numbers are generated with Python's `secrets` module (not `random`),
since they double as the unguessable lookup key for the public
order-confirmation page — anyone with the number can view that one order's
contact details, so treat it a little like a bearer token, not just a
cosmetic reference code.

**Nothing here processes a real payment or touches your bank account** —
it's purely a way to collect an order and its details, then remind both
sides how the payment is expected to happen.

## Mobile API (companion Android app)

`/api/v1/*` is a small JSON API added alongside the HTML admin panel, for
the **RGC Manager** Android app (a separate project — see its own README).
It lets the owner view Orders, Pickup Requests, and the Mailbox, and update
Order/Pickup status, from their phone. It reuses the exact same database
and business logic as `/admin/...` — there's no separate data store, and no
new customer-facing behavior; it's purely another door into data that
already exists.

**Auth is separate from the browser session cookie.** The app signs in once
against `POST /api/v1/login` with the same `ADMIN_USERNAME`/`ADMIN_PASSWORD`
as `/admin/login`, gets back a signed token (itsdangerous, using the same
`SECRET_KEY` as everything else), and sends it as
`Authorization: Bearer <token>` on every request after that. Tokens are
valid for `MOBILE_TOKEN_MAX_AGE_DAYS` (env var, default `180`) days from
when they were issued — there's no server-side revocation list, so a
leaked/lost-phone token stays valid until it expires; rotating `SECRET_KEY`
invalidates every token immediately (and every website login too, per
"Staying logged in" above) if you ever need to cut one off sooner.

Endpoints:

- `POST /api/v1/login` — body `{"username", "password"}` → `{"token", "username", "company_name", "expires_in_seconds"}`.
- `GET /api/v1/me` — current username + `order_statuses`/`pickup_statuses` (so the app never hardcodes them).
- `GET /api/v1/summary` — dashboard counts: `orders_awaiting_payment`, `pickups_requested`, `mailbox_unread_threads`.
- `GET /api/v1/orders` (optional `?status=`) / `GET /api/v1/orders/<id>` / `POST /api/v1/orders/<id>/status` (body `{"status"}`).
- `GET /api/v1/orders/<id>/invoice.pdf` — the automatic invoice for a product Order.
- `GET /api/v1/invoices` — lists manual invoices (newest first), including ones created from the web admin at `/admin/invoices/new`, not just ones the app itself created.
- `POST /api/v1/invoices/manual` — creates a manual invoice (same data model as `/admin/invoices/new`) and returns its PDF directly.
- `GET /api/v1/invoices/<id>/pdf` — the PDF for a manual invoice returned by `/api/v1/invoices` above.
- `GET /api/v1/pickups` (optional `?status=`) / `GET /api/v1/pickups/<id>` / `POST /api/v1/pickups/<id>/status` (body `{"status"}`).
- `GET /api/v1/mailbox` (thread list) / `GET /api/v1/mailbox/<thread_key>` (messages — read-only, marks the thread read, same as `/admin/mailbox`; no reply/compose here either).

All except `/api/v1/login` require the `Authorization: Bearer <token>`
header and return `401` (JSON `{"error": "..."}`) without it or once it
expires. Every other error also comes back as JSON (`{"error": "..."}`)
with an appropriate status code (`400` for a bad/invalid `status` value,
`404` for an order/pickup/thread that doesn't exist) — the global 404
handler special-cases `/api/*` so a bad API URL never comes back as an HTML
page.

No extra Python dependency was needed — `itsdangerous` is already installed
as part of Flask itself.

## Deploying to Render

Costs money once you're past the free tiers (Render web service + a managed
Postgres). If you'd rather run this for $0/month on hardware you already
own, skip to "Self-hosting on your own Ubuntu server" below instead — that
section is the direct replacement for Render + Supabase + Cloudflare R2.

**1. Push this project to a GitHub/GitLab repo**, then in Render: New →
Web Service → connect the repo.

**2. Build & start commands:**

- Build Command: `pip install -r requirements.txt`
- Start Command: `gunicorn app:app`

  (`app:app` means "the `app` object inside `app.py`" — gunicorn binds to
  the `$PORT` Render provides automatically, so no `--bind` flag is needed.)

**3. Add a Postgres database:** in Render, New → PostgreSQL (the free tier
is fine to start). Once created, open your web service → Environment, and
add the database's **Internal Database URL** as `DATABASE_URL`. Render
databases use `postgres://...`; the app already rewrites that to
`postgresql://...` for you.

**Important — Render's free web services have an ephemeral filesystem: it's
wiped on every redeploy.** Since uploaded images (post photos, product
photos, the favicon) now save to local disk (`static/uploads/`,
`static/branding/`) instead of Cloudflare R2, they will **not** survive a
redeploy on Render's free tier. That's fine for self-hosting (see below,
where the disk is permanently yours), but if you deploy to Render, either
upgrade to a paid instance with a [persistent
disk](https://render.com/docs/disks) mounted at `static/uploads` and
`static/branding`, or re-add S3-compatible object storage (R2, S3, etc.) —
ask if you want that added back in.

### Keeping a free-tier instance from spinning down

Render's **free** web services spin down after 15 minutes with no inbound
traffic, then take about a minute to cold-start on the next visit. This app
has a built-in keep-alive for that: whenever it's running on Render (detected
via the `RENDER_EXTERNAL_URL` variable Render sets automatically — nothing to
configure), a background thread pings its own `/healthz` endpoint every 10
minutes, so it never goes quiet long enough to spin down. It does nothing
locally or on a paid instance type that doesn't spin down anyway.

Worth knowing before you rely on it:
- It keeps the service running around the clock, which uses free-tier
  instance hours faster than occasional real visitors would — check Render's
  current free-tier hour limits if you're running multiple free services.
- It's a workaround, not something Render documents or officially supports.
  An external uptime monitor (e.g. [UptimeRobot](https://uptimerobot.com),
  free) pinging `https://your-app.onrender.com/healthz` every few minutes
  does the same job without your app needing to keep a thread alive for it —
  and keeps working even across a deploy/restart timing gap. Either one
  works; you can also run both.
- Set `KEEP_ALIVE_ENABLED=false` if you'd rather turn this off (e.g. once
  you've upgraded past the free tier).

**5. Set the remaining environment variables** on the Render service:
`SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `SMTP_USERNAME`,
`SMTP_PASSWORD`.
Set `SECRET_KEY` to a random string yourself rather than leaving it unset —
see "Staying logged in" above for why that matters.

**6. Deploy.** Render will rebuild on every push; the database (Postgres,
not a local file) survives that fine. See the disk warning above regarding
uploaded images on the free tier.

## Self-hosting on your own Ubuntu server (no Render, Supabase, or Cloudflare)

This replaces all three paid services with one machine you own: an
always-on Ubuntu box on your home network runs the Flask app, its own local
PostgreSQL database, and stores uploaded images on its own disk — the app's
code already supports this with zero changes (image uploads use local disk
by default now; `DATABASE_URL` works with any Postgres, including one
running on `localhost`).

**Trade-offs, up front, since this is different from a managed host:**
- **Uptime depends on your home internet and power**, not a data center's.
  A router reboot, an ISP outage, or a power cut takes the site down until
  it comes back. A cheap UPS (battery backup) for the router + server
  avoids the "brief power blip = hours of downtime while things restart"
  scenario.
- **No automatic managed backups.** Supabase/Render backed up your data for
  you; here, you're responsible for backups (see Step 8 below) — skipping
  this step means a hard drive failure loses everything.
- **Most residential ISPs don't give you a static IP**, so pointing your
  domain at "wherever your home connection currently is" needs either a
  static IP add-on from your ISP (ask if they offer one) or a small
  dynamic-DNS script (Step 7 below) that keeps your domain's DNS record in
  sync with your home IP whenever it changes.
- **In exchange, it's $0/month recurring** (beyond electricity and the
  domain itself, which you already own).

Ready-to-use config files for all of this are in the `deploy/` folder of
this project: `rgc.service` (systemd), `nginx.conf`, `godaddy-ddns.sh`,
`backup.sh`, and `.env.example`.

### Step 1 — Prepare the Ubuntu machine

Any spare PC, mini PC, or old laptop works. You can install either **Ubuntu
Server** (no desktop environment, lighter, managed entirely over SSH) or
**Ubuntu Desktop** (a normal graphical Ubuntu install, if you'd rather have
a screen/keyboard experience) — both run this app identically from here on,
since everything below just runs in a terminal either way. Wired Ethernet is
worth it over Wi-Fi for a machine that needs to stay reachable.

**Installing Ubuntu Desktop specifically:** download the ISO from
[ubuntu.com/download/desktop](https://ubuntu.com/download/desktop), write it
to a USB drive with [Rufus](https://rufus.ie/) (Windows) or
[balenaEtcher](https://etcher.balena.io/) (any OS), boot the target machine
from it, and go through the normal graphical installer ("Install Ubuntu").
Once it's installed and you're logged into the desktop, open a terminal
(**Activities → Terminal**, or `Ctrl+Alt+T`) — every command below runs
there, exactly as it would over SSH on Ubuntu Server.

A few things worth doing on a Desktop install specifically, since it's now
acting as an always-on server rather than a normal desktop:

- **Turn off automatic suspend**: Settings → Power → set "Screen Blank" and
  "Automatic Suspend" to Off (or "Never"). Otherwise the whole machine goes
  to sleep after inactivity and the site goes down with it. If it's a
  laptop, also stop it suspending when the lid closes:
  `sudo nano /etc/systemd/logind.conf`, set `HandleLidSwitch=ignore` (and
  `HandleLidSwitchDocked=ignore`), then `sudo systemctl restart systemd-logind`.
- **Turn off automatic updates that reboot unattended**: Settings →
  Software Updates (or `sudo dpkg-reconfigure unattended-upgrades`) — you
  want to control when this machine restarts, not have it happen mid-order.
- **Enable SSH** so you don't have to sit at the machine for the rest of
  this guide: `sudo apt install -y openssh-server`, then connect from
  another computer with `ssh your-username@192.168.1.50` (see the DHCP
  reservation note below for that IP).

Then, on either Server or Desktop:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-venv python3-pip git nginx postgresql postgresql-contrib \
    certbot python3-certbot-nginx ufw
```

Give the machine a fixed IP on your local network — in your router's admin
page, set a **DHCP reservation** (sometimes called "static lease") for this
machine's MAC address, e.g. `192.168.1.50`, so its local address never
changes even after a reboot.

### Step 2 — Get the app onto the server

If your code lives in a GitHub/GitLab repo:

```bash
sudo mkdir -p /opt/rgcdoortodoor
sudo chown "$USER":"$USER" /opt/rgcdoortodoor
git clone <your-repo-url> /opt/rgcdoortodoor
```

Otherwise, copy the project folder over with `scp`/`rsync` from wherever it
currently lives into `/opt/rgcdoortodoor` on the server.

Create a dedicated, unprivileged user to actually run the app (don't run it
as root or your login user):

```bash
sudo useradd --system --home /opt/rgcdoortodoor --shell /usr/sbin/nologin rgcapp
sudo chown -R rgcapp:rgcapp /opt/rgcdoortodoor
```

### Step 3 — Python environment

```bash
cd /opt/rgcdoortodoor
sudo -u rgcapp python3 -m venv venv
sudo -u rgcapp ./venv/bin/pip install -r requirements.txt
```

### Step 4 — Set up PostgreSQL locally (replaces Supabase)

```bash
sudo -u postgres psql -c "CREATE USER rgc WITH PASSWORD 'choose-a-strong-password';"
sudo -u postgres psql -c "CREATE DATABASE rgc OWNER rgc;"
```

Note the password — it goes into `DATABASE_URL` next. Postgres here only
needs to accept connections from `localhost` (the default), since the app
runs on the same machine.

### Step 5 — Environment variables

```bash
cp deploy/.env.example /opt/rgcdoortodoor/.env
nano /opt/rgcdoortodoor/.env   # fill in real values
sudo chown rgcapp:rgcapp /opt/rgcdoortodoor/.env
sudo chmod 600 /opt/rgcdoortodoor/.env
```

Set `DATABASE_URL=postgresql://rgc:that-password@localhost:5432/rgc` and
fill in `SECRET_KEY`, `ADMIN_PASSWORD`, and your SMTP credentials (see
"Sending email via Microsoft 365 SMTP" above — that part is unaffected by
where the app is hosted).

### Step 6 — Run it as a service (replaces Render's process management)

```bash
sudo cp deploy/rgc.service /etc/systemd/system/rgc.service
sudo systemctl daemon-reload
sudo systemctl enable --now rgc
sudo systemctl status rgc   # should show "active (running)"
```

This starts the app on boot and restarts it automatically if it ever
crashes — the two things Render was doing for you. `journalctl -u rgc -f`
tails its logs.

### Step 7 — Nginx + HTTPS + your domain

```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/rgc
sudo ln -s /etc/nginx/sites-available/rgc /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

**Router port forwarding:** in your router's admin page, forward external
ports **80** and **443** to this machine's local IP (the one you reserved
in Step 1) on the same ports. Also open the firewall on the machine itself:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
```

**Pointing the domain here:** first check whether your ISP already gives
you a static IP (worth a quick call/chat if unsure) — if so, just set an
**A record** for `rgcdoortodoorboxservices.ca` (and `www`) in GoDaddy's DNS
manager to that IP, and you're done with this part.

If your IP changes periodically (most home connections), use
`deploy/godaddy-ddns.sh`: fill in a [GoDaddy API key/secret](https://developer.godaddy.com/keys)
at the top, then run it on a cron job:

```bash
chmod +x deploy/godaddy-ddns.sh
crontab -e
# add this line:
*/10 * * * * /opt/rgcdoortodoor/deploy/godaddy-ddns.sh >> /var/log/rgc-ddns.log 2>&1
```

It checks your current public IP every 10 minutes and updates the domain's
A record only when it's actually changed.

**HTTPS**, once DNS is pointed at your IP and port-forwarding is live:

```bash
sudo certbot --nginx -d rgcdoortodoorboxservices.ca -d www.rgcdoortodoorboxservices.ca
```

Certbot edits `/etc/nginx/sites-available/rgc` to add the HTTPS server block
and redirect HTTP to it, and sets up its own auto-renewal — nothing further
to do for that.

### Step 8 — Backups (replaces Supabase's managed backups)

```bash
chmod +x deploy/backup.sh
sudo -u rgcapp crontab -e
# add this line:
0 3 * * * /opt/rgcdoortodoor/deploy/backup.sh >> /var/log/rgc-backup.log 2>&1
```

This dumps the database and archives uploaded images nightly, keeping 14
days locally. For real protection against this machine itself failing
(drive failure, fire, theft — not just a bad deploy), also copy backups
somewhere else periodically — an external USB drive, or a free-tier cloud
storage account via [rclone](https://rclone.org/) — see the comment at the
bottom of `backup.sh`.

### Updating the app later

```bash
cd /opt/rgcdoortodoor
sudo -u rgcapp git pull
sudo -u rgcapp ./venv/bin/pip install -r requirements.txt
sudo systemctl restart rgc
```

### One thing worth testing early

Outbound email now goes through Microsoft 365 **SMTP** again (port 587),
having briefly used Mailgun's HTTPS API instead. Some residential ISPs block
outbound SMTP ports (587/25) to cut down on spam from home connections — if
this server is on a residential line rather than a proper hosting/VPS
provider, confirm the contact form and order emails actually send once
you're live. If they silently fail, check whether your ISP blocks those
ports before assuming it's a code or credentials problem.

## Pages

Public:
- `/` — Home (also shows latest updates + a quick tracking box)
- `/about-us` — About Us
- `/contact-us` — Contact Us (working contact form with flash messages)
- `/privacy-policy` — Privacy Policy
- `/terms-and-conditions` — Terms and Conditions
- `/empty-box-sales` — Empty Box Sales
- `/packaging-items` — Packaging Items
- `/rates` — Rates
- `/sari-sari` — Sari Sari by: Regueca (shows Sari-Sari-category products once any are posted)
- `/updates` — Updates & Announcements list (shown in the nav as "RGC Blog"), `/updates/<id>` for one post
- `/track` — Track Your Package (enter a tracking number)
- `/cart` — shopping cart, `/cart/add/<product_id>`, `/cart/update/<product_id>`,
  `/cart/remove/<product_id>` (all POST)
- `/checkout` — customer details + Interac e-Transfer instructions,
  `/order-confirmation/<order_number>` — the receipt/instructions page
- `/healthz` — Bare-bones health check ("OK"); used by the built-in keep-alive
  and/or an external uptime monitor

Admin (password-protected):
- `/admin/login`, `/admin/logout`
- `/admin`, `/admin/posts/new`, `/admin/posts/<id>/edit`, `/admin/posts/<id>/delete`
- `/admin/mailbox` (conversation list, read-only), `/admin/mailbox/<thread_key>`
  (one conversation, marks it read)
- `/admin/orders` (list), `/admin/orders/<id>` (detail), `/admin/orders/<id>/status`
  (POST — change Awaiting Payment / Paid / Fulfilled / Cancelled)
- `/admin/products`, `/admin/products/new`, `/admin/products/<id>/edit`,
  `/admin/products/<id>/delete` (filter the list with `?category=packaging`,
  `?category=box`, or `?category=sari-sari`)
- `/admin/subscribers` (list), `/admin/subscribers/export.csv` (download),
  `/admin/subscribers/<id>/delete` (POST)
- `/admin/pages` (list), `/admin/pages/<slug>/edit` (Privacy Policy, Terms
  and Conditions, Contact Us intro)
- `/admin/settings`, `/admin/settings/favicon/remove`

Mobile API (JSON, token-protected — see "Mobile API" above):
- `/api/v1/login` (POST), `/api/v1/me`, `/api/v1/summary`
- `/api/v1/orders`, `/api/v1/orders/<id>`, `/api/v1/orders/<id>/status` (POST), `/api/v1/orders/<id>/invoice.pdf`
- `/api/v1/invoices`, `/api/v1/invoices/manual` (POST), `/api/v1/invoices/<id>/pdf`
- `/api/v1/pickups`, `/api/v1/pickups/<id>`, `/api/v1/pickups/<id>/status` (POST)
- `/api/v1/mailbox`, `/api/v1/mailbox/<thread_key>`

## Structure

```
app.py
requirements.txt
templates/
    base.html
    home.html
    about_us.html
    contact_us.html
    privacy_policy.html
    terms_and_conditions.html
    empty_box_sales.html
    packaging_items.html
    rates.html
    sari_sari.html
    updates.html
    update_detail.html
    track.html
    cart.html
    checkout.html
    order_confirmation.html
    _product_grid.html
    404.html
    admin/
        login.html
        dashboard.html
        post_form.html
        mailbox.html
        mailbox_thread.html
        subscribers.html
        orders.html
        order_detail.html
        products.html
        product_form.html
        pages.html
        page_form.html
        settings.html
        _adminbar.html
static/
    css/style.css
    js/main.js
    images/     logo.webp, hero-flyer.png (site branding/promo images)
    uploads/    (created automatically — post/product photos)
    branding/   (created automatically — site favicon)
deploy/
    rgc.service       systemd unit (Step 6 of self-hosting)
    nginx.conf        Nginx reverse-proxy config (Step 7)
    godaddy-ddns.sh   dynamic-DNS updater (Step 7)
    backup.sh         nightly DB + image backup (Step 8)
    .env.example      template for the server's .env file
.gitignore
```

## Notes

- The contact form emails submissions via Microsoft 365 SMTP (see "Sending
  email via Microsoft 365 SMTP" above). Without `SMTP_PASSWORD` set, it
  still shows its confirmation message but doesn't send anywhere.
- The admin Mailbox (`/admin/mailbox`) only shows contact-form/pickup-request
  submissions and replies sent from it — not a live connection to the real
  Microsoft 365 inbox, and no mirror of other incoming mail. See "Admin
  Mailbox" above for why (GoDaddy-managed tenants don't expose Entra
  ID/Graph API access, and Microsoft retired basic-auth IMAP tenant-wide in
  2023).
- The admin login is a single shared password (no per-user accounts). That's
  enough for a one-person shop; if the owner ever needs multiple staff
  logins with different permissions, that would need a proper user table
  added to `app.py`.
- Uploaded images are capped at 5 MB and limited to PNG/JPG/JPEG/GIF/WEBP,
  and are saved to this app's own `static/uploads/`/`static/branding/`
  folders — back these up along with the database (see "Self-hosting" above)
  since they live only on this server's disk, not in any cloud storage.
- Privacy Policy, Terms and Conditions, and the Contact Us intro are plain
  text edited from `/admin/pages` — no HTML/markup, just blank lines between
  paragraphs. About Us keeps its hand-built timeline/cards layout and isn't
  editable from admin; changing it needs a code edit.
- Checkout (see "Checkout & Orders" above) doesn't process a real payment —
  there's no gateway integration, since Interac e-Transfer has no public API
  for that. It collects the order and emails/displays payment instructions;
  you confirm payment by hand in your online banking and mark the order Paid
  in `/admin/orders`.
- The newsletter signup form just saves an email address to the `Subscriber`
  table — this app has no way to actually send a newsletter. Export the list
  as CSV from `/admin/subscribers` and import it into whatever tool you use
  to send campaigns.
