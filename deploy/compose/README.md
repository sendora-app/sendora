# Sendora with Docker Compose

Ready-to-use Compose files that run the published image `ghcr.io/sendora-app/sendora`. Nothing is built locally.

| File | Purpose |
|---|---|
| `docker-compose.yml` | Sendora, reachable on this machine (default `http://localhost:8080`) |
| `docker-compose.https.yml` | Optional override: Caddy in front with automatic HTTPS (Let's Encrypt) for a public server |
| `Caddyfile` | Caddy configuration used by the HTTPS override |
| `.env.example` | Compose variables: image version, port, domain, data and key location |
| `sendora.env.example` | Optional application settings (`SENDORA_<SETTING>`), read-only in the admin screen |

`.env`, `sendora.env`, `database.key` and `data/` are git-ignored: they hold your own configuration, secrets and data.

## First start

1. Copy this folder to the server and create your configuration:

   ```sh
   cp .env.example .env
   cp sendora.env.example sendora.env   # optional
   ```

   Set `SENDORA_VERSION` in `.env` to a released version (see the releases on GitHub); pin it rather than using `latest`.

2. Create the database key **once** and back it up immediately (password manager or other protected off-site storage). It is exactly 32 random bytes; losing it makes the database and all backups unreadable:

   ```sh
   (umask 077; set -C; openssl rand 32 > database.key)
   mkdir -p data
   ```

   On **Linux**, the container runs as UID/GID 10001 and needs to own the data folder and read the key:

   ```sh
   sudo chown 10001:10001 data && sudo chmod 700 data
   sudo chown root:10001 database.key && sudo chmod 0440 database.key
   ```

   (Docker Desktop on macOS handles ownership itself. **On Windows** a key in a normal folder is refused: Docker Desktop shows it to the container with the permissions `rwxrwxrwx`, and Sendora rejects a key that other users could read. These Compose files have not been tested on Windows; the tested way to run Sendora on Windows is the [single-container steps with Docker volumes](../../docs/quickstart-docker.md#windows-powershell).)

3. Start with database creation allowed, read the one-time setup code and create the administrator account:

   ```sh
   SENDORA_DB_INITIALIZE=true docker compose up -d
   docker compose logs sendora | grep "setup code"
   ```

   Open `APP_URL` (default http://localhost:8080), enter the code and create the administrator.

4. Restart without the initialization switch; from now on `docker compose up -d` is enough:

   ```sh
   docker compose up -d --force-recreate
   ```

## Public server with HTTPS

Point a DNS name (for example `files.example.com`) to the server, open ports 80 and 443, set `SENDORA_DOMAIN=files.example.com` in `.env`, and start with both files:

```sh
docker compose -f docker-compose.yml -f docker-compose.https.yml up -d
```

Caddy obtains and renews the certificate, sets `APP_URL=https://<domain>` for Sendora and forwards the real visitor address (`SENDORA_TRUSTED_PROXIES` is preset to Caddy's internal network), so rate limits and address blocking work per visitor. Sendora itself is then not published on a host port.

The Caddy image is pinned by version and digest. Like Sendora it runs with a read-only filesystem (it writes only to its `caddy_data`/`caddy_config` volumes and a small `/tmp`), without new privileges and with all capabilities dropped except binding ports 80 and 443, and with memory, CPU and process limits.

## Resource limits

Both files set limits per container: Sendora gets 1 GiB memory, 2 CPUs and at most 200 processes/threads (`mem_limit`, `cpus`, `pids_limit`), Caddy 512 MiB and 1 CPU. That is plenty for normal use. If the container is stopped with exit code 137 (out of memory) during very large transfers or a database import, raise `mem_limit` in `docker-compose.yml`. The `/tmp` tmpfs counts towards the memory limit.

The image has a built-in health check (`sendora healthcheck`); `docker compose ps` shows `healthy` once Sendora answers.

## Settings

Every admin setting can be set in `sendora.env` as `SENDORA_<SETTING>`, including SMTP and login providers such as Microsoft Entra ID; the full list is in [docs/configuration.md](../../docs/configuration.md). Values set there win at every start and are read-only in Admin → Settings; an invalid value stops the container with a message naming the variable (`docker compose logs sendora`). Apply changes with `docker compose up -d --force-recreate`.

Passwords and client secrets in `sendora.env` are plain text on the server; protect the file (`chmod 600 sendora.env`). To keep them out of the environment, mount a file and use the `_FILE` form instead, for example `SENDORA_SMTP_PASSWORD_FILE=/run/secrets/smtp_password` with an extra Compose secret.

## Upgrades

1. Read the [changelog](../../CHANGELOG.md) and make a backup (below).
2. Change `SENDORA_VERSION` in `.env`, then `docker compose pull && docker compose up -d`.
3. Check `docker compose logs sendora`. Database migrations run at start and only add tables or columns; going back to an older version means restoring the backup.

## Backups

Admin → Backups makes encrypted database backups, but they do not contain the shared files. For a complete backup stop the container and copy the whole `data` folder, and keep the database key separately:

```sh
docker compose stop
tar -czf sendora-backup-$(date +%F).tar.gz data
docker compose start
```

More: [Upgrades and backups](https://github.com/sendora-app/sendora/wiki/Upgrades-and-Backups).
