# HyperSoar lab: a sandbox and a production stack

Runs the phase 0 production stack (`deploy/deca/docker-compose.yml`) twice on one VM with Docker, so the
owner can use it. **Lab only.** Each stack has its own database, secrets directory, network, Temporal,
console and tunnel URL:

| | Sandbox (`deca-lab`) | Production (`deca-prod`) |
|---|---|---|
| Compose files | base + `docker-compose.lab.yml` + `docker-compose.sandbox.yml` | base + `docker-compose.lab.yml` + `docker-compose.production.yml` |
| `HYPERSOAR_ETC` / data | `/etc/deca-soar`, `/var/lib/deca-soar` | `/etc/deca-soar-prod`, `/var/lib/deca-soar-prod` |
| `HYPERSOAR_LAB_NET` | `172.30.124` | `172.30.125` |
| Install mode | sandbox | production, from an empty database |
| Alerts | seeding bot (`synth`) + configured data sources | configured data sources only |
| Lark / Jira / 9router | mocks | live only (nothing configured yet) |
| Scenario runner, Scenario page | yes | no (CLI refuses, page and API answer 404) |
| Integration settings API | writes on | read-only until security review |

| Production (phase 0) | Lab stand-in |
|---|---|
| RDS PostgreSQL, TLS | `postgres` container, TLS (lab CA), `hostssl` + scram only, not published |
| Temporal 1.32.2 under systemd | `temporal` container built from the same release binaries, scripts and config, mTLS |
| SLS detection results | sandbox only: `synth`, synthetic WAF/SAS alerts (`raw_ref` `synthetic://lab`) appended to the replay file |
| Anchor file shipped by Logtail to SLS | anchor file stays on the VM (`/var/lib/deca-soar/anchors`) |
| LLM triage | mock (unchanged) |
| (none) | `console`: SOC console, own viewer DB role, one login, writes through the broker as the human principal of the same name (re-typed password); `tunnel`: Cloudflare quick tunnel |

Not published on the host: Postgres, Temporal (no UI, HTTP API off), the broker. The only way in from
outside is the tunnel to the console (HTTPS, login with rate limit). The broker runs with
`HYPERSOAR_ENV=lab` because `policy/protected.yaml` still holds placeholders and the synthetic alerts use
TEST-NET addresses; every action stays shadow.

## Bring-up

Run as a sudoer on the VM, repo checked out at the commit to deploy (`$REPO`, `$SHA` = `git rev-parse HEAD`).
The steps are for the sandbox; for the production stack run `lab_setup.py` with
`-e HYPERSOAR_LAB_ROOT=/etc/deca-soar-prod -e HYPERSOAR_LAB_DATA=/var/lib/deca-soar-prod -e HYPERSOAR_LAB_SUBNET=172.30.125.0/24`
(mounting those directories), use `-p deca-prod`, `docker-compose.production.yml`, `/etc/deca-soar-prod/deca.env`
and the `.125` addresses, and leave out `HYPERSOAR_REPLAY_DIR`.

1. Images:
   ```sh
   docker build -f deploy/deca/Dockerfile -t hypersoar:$SHA .
   deploy/lab/fetch-temporal.sh /var/cache/deca-lab/temporal
   deploy/lab/build-temporal.sh /var/cache/deca-lab/temporal
   ```
2. Secrets. On the operator machine, generate the owner password and the console password, keep both in
   the operator's vault, and hash the console password (`hypersoar console-hash` reads it on stdin). Send
   only `{"owner_password": ..., "console_hash": ...}` on stdin:
   ```sh
   <json> | sudo docker run --rm -i --user 0 --network none -v /etc/deca-soar:/etc/deca-soar \
     -v /var/lib/deca-soar:/var/lib/deca-soar -v $REPO/deploy/lab/lab_setup.py:/lab_setup.py:ro \
     hypersoar:$SHA python /lab_setup.py
   ```
   Then write `/etc/deca-soar/deca.env` (no secrets):
   ```
   HYPERSOAR_IMAGE=hypersoar:<sha>
   HYPERSOAR_GIT_SHA=<sha>
   HYPERSOAR_BASE_IMAGE=<base image digest from deploy/deca/Dockerfile>
   HYPERSOAR_TEMPORAL_ADDRESS=172.30.124.10:7233
   HYPERSOAR_BROKER_URL=https://broker:8100
   HYPERSOAR_BIND_IP=172.30.124.1
   HYPERSOAR_REPLAY_DIR=/var/lib/deca-soar/replay
   HYPERSOAR_ANCHOR_DIR=/var/lib/deca-soar/anchors
   HYPERSOAR_POLICY_HOST_DIR=<repo>/policy
   HYPERSOAR_ETC=/etc/deca-soar
   HYPERSOAR_LAB_NET=172.30.124
   HYPERSOAR_LAB_MODE=sandbox
   HYPERSOAR_LAB_PROJECT=deca-lab
   HYPERSOAR_OWNER_OUT_DIR=/etc/deca-soar/out
   ```
3. Database and Temporal:
   ```sh
   C="docker compose -p deca-lab -f deploy/deca/docker-compose.yml -f deploy/lab/docker-compose.lab.yml -f deploy/lab/docker-compose.sandbox.yml --env-file /etc/deca-soar/deca.env"
   $C up -d postgres
   sudo cat /etc/deca-soar/lab/db-bootstrap.sql | $C exec -T -u postgres postgres psql -v ON_ERROR_STOP=1 -q
   $C up -d temporal
   $C exec -e TEMPORAL_ADDRESS=172.30.124.10:7233 -e TEMPORAL_TLS_CERT=/etc/deca-soar/temporal/tls/operator.pem \
     -e TEMPORAL_TLS_KEY=/etc/deca-soar/temporal/tls/operator.key \
     -e TEMPORAL_TLS_CA=/etc/deca-soar/temporal/tls/server-ca.pem \
     -e TEMPORAL_TLS_SERVER_NAME=temporal.deca.internal temporal /opt/temporal/bin/temporal-namespace.sh
   ```
4. Owner jobs, then the service logins (RUNBOOK section 5):
   ```sh
   <owner DSN> | sudo HYPERSOAR_OWNER_COMPOSE_OVERRIDE=$REPO/deploy/lab/docker-compose.owner.lab.yml \
     deploy/deca/bin/deca-owner-run.sh migrate
   <owner DSN> | sudo HYPERSOAR_OWNER_COMPOSE_OVERRIDE=... deploy/deca/bin/deca-owner-run.sh create-principal \
     --name temporal-worker --kind service --role analyst --token-file /out/worker.token
   sudo mv /etc/deca-soar/out/worker.token /etc/deca-soar/secrets/deca_broker_worker_token
   # The console user's broker principal (same name as HYPERSOAR_CONSOLE_USER) and its re-auth password:
   <owner DSN> | sudo ... deploy/deca/bin/deca-owner-run.sh create-principal \
     --name owner --kind human --role admin --token-file /out/console.token
   sudo mv /etc/deca-soar/out/console.token /etc/deca-soar/secrets/deca_broker_console_token
   (<owner DSN>; <console password>) | sudo ... deploy/deca/bin/deca-owner-run.sh set-reauth --name owner --actor ops
   # L3 approvals only from the console's own token (v0.9):
   <owner DSN> | sudo ... deploy/deca/bin/deca-owner-run.sh set-channel --name owner --channel console --actor ops
   sudo cat /etc/deca-soar/lab/db-logins.sql | $C exec -T -u postgres postgres psql -v ON_ERROR_STOP=1 -q
   sudo shred -u /etc/deca-soar/lab/db-bootstrap.sql /etc/deca-soar/lab/db-logins.sql
   ls /dev/shm   # no deca-owner.* left
   ```
   With another stack set `HYPERSOAR_ENV_FILE` and `HYPERSOAR_SECRETS_DIR` for `deca-owner-run.sh`.
   The owner DSN is `postgresql://deca_owner:<pw>@postgres:5432/deca_soar?sslmode=verify-full&sslrootcert=/run/secrets/deca_db_ca`.
5. Services, anchor job and the public URL:
   ```sh
   $C up -d
   $C --profile jobs run --rm ledger-anchor
   $C logs tunnel | grep -o 'https://[a-z0-9-]*\.trycloudflare\.com'
   ```

Hourly anchor (the lab has no systemd unit for the overlay): a user crontab line
`15 * * * * cd $REPO && $C --profile jobs run --rm ledger-anchor >> ~/deca-lab-logs/anchor.log 2>&1`.

Changing the console password. The console login (`secrets/console_password_hash`) and the broker
re-auth password of the same principal (`set-reauth`) are stored separately; changing one does not change
the other. Every time `console_password_hash` is replaced, run `set-reauth` for that principal with the
same new password on the same stack, otherwise human writes from the console are refused:
```sh
<new console password> | hypersoar console-hash > console_password_hash.new   # operator machine
sudo install -m 0400 -o 10001 console_password_hash.new /etc/deca-soar/secrets/console_password_hash
(<owner DSN>; <new console password>) | sudo ... deploy/deca/bin/deca-owner-run.sh set-reauth --name owner --actor ops
$C restart console
```
A redeploy keeps the existing secrets directory (`lab_setup.py` refuses to overwrite it), so do not
re-run `set-reauth` with an old password from an earlier setup.

The quick tunnel URL changes whenever the `tunnel` container restarts. To stop everything:
`$C down` (add `-v` to drop the database volume).
