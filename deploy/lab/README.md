# DECA SOAR lab (shadow mode, synthetic data)

Runs the phase 0 production stack (`deploy/deca/docker-compose.yml`) on one VM with Docker, so the owner
can watch it working. **Lab only.** Nothing here is a production setting, and the data is synthetic.

| Production (phase 0) | Lab stand-in |
|---|---|
| RDS PostgreSQL, TLS | `postgres` container, TLS (lab CA), `hostssl` + scram only, not published |
| Temporal 1.32.2 under systemd | `temporal` container built from the same release binaries, scripts and config, mTLS |
| SLS detection results | `synth`: synthetic WAF/SAS alerts (`raw_ref` `synthetic://lab`) appended to the replay file |
| Anchor file shipped by Logtail to SLS | anchor file stays on the VM (`/var/lib/deca-soar/anchors`) |
| LLM triage | mock (unchanged) |
| (none) | `console`: read-only SOC view, own viewer DB role, one login; `tunnel`: Cloudflare quick tunnel |

Not published on the host: Postgres, Temporal (no UI, HTTP API off), the broker. The only way in from
outside is the tunnel to the console (HTTPS, login with rate limit). The broker runs with
`DECA_ENV=lab` because `policy/protected.yaml` still holds placeholders and the synthetic alerts use
TEST-NET addresses; every action stays shadow.

## Bring-up

Run as a sudoer on the VM, repo checked out at the commit to deploy (`$REPO`, `$SHA` = `git rev-parse HEAD`).

1. Images:
   ```sh
   docker build -f deploy/deca/Dockerfile -t deca-soar:$SHA .
   deploy/lab/fetch-temporal.sh /var/cache/deca-lab/temporal
   docker build --build-context temporalbin=/var/cache/deca-lab/temporal \
     -f deploy/lab/temporal.Dockerfile -t deca-lab-temporal:1.32.2 .
   ```
2. Secrets. On the operator machine, generate the owner password and the console password, keep both in
   the operator's vault, and hash the console password (`deca-soar console-hash` reads it on stdin). Send
   only `{"owner_password": ..., "console_hash": ...}` on stdin:
   ```sh
   <json> | sudo docker run --rm -i --user 0 --network none -v /etc/deca-soar:/etc/deca-soar \
     -v /var/lib/deca-soar:/var/lib/deca-soar -v $REPO/deploy/lab/lab_setup.py:/lab_setup.py:ro \
     deca-soar:$SHA python /lab_setup.py
   ```
   Then write `/etc/deca-soar/deca.env` (no secrets):
   ```
   DECA_SOAR_IMAGE=deca-soar:<sha>
   DECA_GIT_SHA=<sha>
   DECA_BASE_IMAGE=<base image digest from deploy/deca/Dockerfile>
   DECA_TEMPORAL_ADDRESS=172.30.124.10:7233
   DECA_BROKER_URL=https://broker:8100
   DECA_BIND_IP=172.30.124.1
   DECA_REPLAY_DIR=/var/lib/deca-soar/replay
   DECA_ANCHOR_DIR=/var/lib/deca-soar/anchors
   DECA_POLICY_HOST_DIR=<repo>/policy
   ```
3. Database and Temporal:
   ```sh
   C="docker compose -p deca-lab -f deploy/deca/docker-compose.yml -f deploy/lab/docker-compose.lab.yml --env-file /etc/deca-soar/deca.env"
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
   <owner DSN> | sudo DECA_OWNER_COMPOSE_OVERRIDE=$REPO/deploy/lab/docker-compose.owner.lab.yml \
     deploy/deca/bin/deca-owner-run.sh migrate
   <owner DSN> | sudo DECA_OWNER_COMPOSE_OVERRIDE=... deploy/deca/bin/deca-owner-run.sh create-principal \
     --name temporal-worker --kind service --role analyst --token-file /out/worker.token
   sudo mv /etc/deca-soar/out/worker.token /etc/deca-soar/secrets/deca_broker_worker_token
   sudo cat /etc/deca-soar/lab/db-logins.sql | $C exec -T -u postgres postgres psql -v ON_ERROR_STOP=1 -q
   sudo shred -u /etc/deca-soar/lab/db-bootstrap.sql /etc/deca-soar/lab/db-logins.sql
   ls /dev/shm   # no deca-owner.* left
   ```
   The owner DSN is `postgresql://deca_owner:<pw>@postgres:5432/deca_soar?sslmode=verify-full&sslrootcert=/run/secrets/deca_db_ca`.
5. Services, anchor job and the public URL:
   ```sh
   $C up -d
   $C --profile jobs run --rm ledger-anchor
   $C logs tunnel | grep -o 'https://[a-z0-9-]*\.trycloudflare\.com'
   ```

The quick tunnel URL changes whenever the `tunnel` container restarts. To stop everything:
`$C down` (add `-v` to drop the database volume).
