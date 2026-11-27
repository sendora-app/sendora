# Quick start: Docker (one command)

The bare minimum to try Sendora on your own machine with the published image. For a lasting setup use the [Docker Compose files](../deploy/compose/README.md); for a cluster see the [Kubernetes quick start](quickstart-kubernetes.md).

[Back to the documentation index](README.md)

## 1. Folder and database key

```sh
mkdir sendora && cd sendora
mkdir data
(umask 077; set -C; openssl rand 32 > database.key)
```

The key is exactly 32 random bytes and encrypts the database and the stored share files. **Keep a copy in a safe place**: without it the data cannot be read, and it cannot be regenerated.

On **Linux** the container runs as UID/GID 10001 and must own the data folder and be able to read the key:

```sh
sudo chown 10001:10001 data && sudo chmod 700 data
sudo chown root:10001 database.key && sudo chmod 0440 database.key
```

(Docker Desktop on macOS handles this itself. On Windows use the PowerShell steps below.)

### Windows (PowerShell)

Tested on Windows 11 Pro with Docker Desktop (WSL 2 backend), in Windows PowerShell 5.1 and in PowerShell 7.7.

Keep the key and the data in Docker volumes, not in Windows folders. The bash command above does not work on Windows, and a key in a Windows folder is refused:

- Windows has no `openssl` by default, and in Windows PowerShell 5.1 the `>` redirect re-encodes the output: in the test, 32 random bytes became a 72-byte file, which is not a valid key. PowerShell 7 keeps the bytes.
- Docker Desktop shows a file from a Windows folder to the container with the permissions `rwxrwxrwx`, and Sendora refuses a key that other users could read (`database key must be a restricted regular file`).

A key made inside Docker has the right permissions. It is created in a small throw-away container (`alpine`, removed afterwards), and the volume `sendora-key` keeps it:

```powershell
docker volume create sendora-key
docker volume create sendora-data
docker run --rm -v sendora-key:/k alpine sh -c "umask 077 && head -c 32 /dev/urandom > /k/database.key && chown -R 10001:10001 /k"
```

**Back up the key now.** Without it nobody can read the data. Copy it to the current folder:

```powershell
docker run --rm -v sendora-key:/k -v "${PWD}:/out" alpine cp /k/database.key /out/database.key
```

Keep that file in a password manager, on offline storage or a USB stick, not on the same machine only. If your password manager prefers text, this prints the key as 44 characters:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$PWD\database.key"))
```

**Restore the key** into a new volume, for example on a new computer or after the volume was removed. If you only have the 44 characters, first make the file again (replace the text):

```powershell
[IO.File]::WriteAllBytes("$PWD\database.key", [Convert]::FromBase64String("PASTE-THE-44-CHARACTERS-HERE"))
```

Then put the file into the volume (this also sets the permissions Sendora requires):

```powershell
docker volume create sendora-key
docker run --rm -v sendora-key:/k -v "${PWD}:/in:ro" alpine sh -c "cp /in/database.key /k/database.key && chown -R 10001:10001 /k && chmod 400 /k/database.key"
```

Do not delete the `sendora-key` volume (`docker volume rm`, or a clean-up such as `docker system prune --volumes`) before you have a copy: without the key the data cannot be read.

## 2. Start

```sh
docker run -d --name sendora -p 127.0.0.1:8080:8080 \
  -v "$PWD/data:/data" \
  -v "$PWD/database.key:/run/secrets/database.key:ro" \
  -e SENDORA_DB_KEY_FILE=/run/secrets/database.key \
  -e SENDORA_DB_INITIALIZE=true \
  -e APP_URL=http://localhost:8080 \
  ghcr.io/sendora-app/sendora:0.3.0
```

### Windows (PowerShell)

The backtick (`` ` ``) continues a command on the next line:

```powershell
docker run -d --name sendora -p 127.0.0.1:8080:8080 `
  -v sendora-data:/data `
  -v sendora-key:/run/secrets:ro `
  -e SENDORA_DB_KEY_FILE=/run/secrets/database.key `
  -e SENDORA_DB_INITIALIZE=true `
  -e APP_URL=http://localhost:8080 `
  ghcr.io/sendora-app/sendora:0.3.0
docker logs sendora | Select-String "setup code"
```

## 3. Create the administrator

```sh
docker logs sendora | grep "setup code"
```

Open http://localhost:8080, enter the setup code and create the administrator account. The code is printed only while no account exists and changes on every restart: always use the last line. More ways to find it: [First-run setup code](https://github.com/sendora-app/sendora/wiki/Accounts-and-Authentication#first-run-setup-code).

## 4. Later starts

`SENDORA_DB_INITIALIZE=true` is only for creating the database the very first time. Recreate the container without it:

```sh
docker rm -f sendora
docker run -d --name sendora --restart unless-stopped -p 127.0.0.1:8080:8080 \
  -v "$PWD/data:/data" \
  -v "$PWD/database.key:/run/secrets/database.key:ro" \
  -e SENDORA_DB_KEY_FILE=/run/secrets/database.key \
  -e APP_URL=http://localhost:8080 \
  ghcr.io/sendora-app/sendora:0.3.0
```

Windows (PowerShell):

```powershell
docker rm -f sendora
docker run -d --name sendora --restart unless-stopped -p 127.0.0.1:8080:8080 `
  -v sendora-data:/data `
  -v sendora-key:/run/secrets:ro `
  -e SENDORA_DB_KEY_FILE=/run/secrets/database.key `
  -e APP_URL=http://localhost:8080 `
  ghcr.io/sendora-app/sendora:0.3.0
```

Any admin setting can be added as `-e SENDORA_<SETTING>=value` (see [Configuration](configuration.md#settings-from-a-configmap-or-environment-variables)). To stop: `docker rm -f sendora`; your data stays in `data/` (on Windows: in the `sendora-data` volume).

## Next steps

- Reachable from other machines or the internet: use the [Compose files with automatic HTTPS](../deploy/compose/README.md#public-server-with-https).
- Outgoing mail, sign-in with Microsoft Entra ID and other settings: [Configuration](configuration.md), [Email](https://github.com/sendora-app/sendora/wiki/Email-and-Notifications), [Accounts and authentication](https://github.com/sendora-app/sendora/wiki/Accounts-and-Authentication).
- Backups: [Upgrades and backups](https://github.com/sendora-app/sendora/wiki/Upgrades-and-Backups).
- Check that an image really comes from this project's release workflow: [verifying images](../SECURITY.md#verifying-release-images). The image has a built-in health check (`docker ps` shows `healthy` once Sendora answers).
