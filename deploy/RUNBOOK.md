# Runbook deploy produksi — SOAR DECA Fase 0 (§12.2 tahap 1, shadow)

Status: **belum pernah dijalankan di Alibaba.** Compose belum dieksekusi dengan Docker (mesin build tanpa Docker).
Yang sudah diuji di stack sekali pakai (`.venv/bin/python e2e/run_e2e.py --evidence <dir-di-luar-repo>`; stack
mati dan folder run dihapus di akhir): binary Temporal server 1.32.2 dengan config `deploy/temporal/config`
yang sama, skema via `temporal-schema.sh`, namespace via `temporal-namespace.sh`, mTLS, lalu gateway → workflow
Temporal → broker shadow → ledger. Item bertanda **[A]** harus dicek di console Alibaba sebelum deploy.

Mesin workflow = **Temporal server self-hosted (MIT) + Python SDK `temporalio`**. Tidak memakai Temporal Cloud,
fitur berbayar, atau Web UI. Operator memakai `temporal` CLI dengan sertifikat operator lewat mTLS.

## 0. Prasyarat (disiapkan owner/ops, bukan dari repo)
| Komponen | Isi |
|---|---|
| ECS (2–4 vCPU/8 GiB) | Temporal server (systemd) + gateway/worker/broker (Docker compose); tanpa EIP |
| RDS PostgreSQL | DB `temporal`, `temporal_visibility` (owner user `temporal`), `deca_soar` (owner user `deca_owner`); TLS on **[A] versi ≥ 12** |
| Security group | 7233 (Temporal frontend) dan 8100 (broker) hanya dari ECS ini + bastion operator; 7234/7235/6933–6939 hanya dari ECS ini; RDS hanya dari ECS ini |
| Egress | tidak ada internet keluar di fase 0, kecuali registry image (atau mirror ACR) |
| PKI internal | CA server Temporal, CA klien DECA (sertifikat gateway, worker, operator), CA broker |

Tidak ada kredensial tulis Alibaba di mana pun. Broker dan worker menolak start bila `ALIBABA_CLOUD_ACCESS_KEY_*`,
`ALICLOUD_*` atau `DECA_SOAR_ACTOR_ROLE_ARN` ada di env. Worker juga menolak start bila memegang URL DB atau key vault.

## 1. Binary Temporal
```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin temporal
curl -fLO https://github.com/temporalio/temporal/releases/download/v1.32.2/temporal_1.32.2_linux_amd64.tar.gz
sudo install -d /opt/temporal/1.32.2 && sudo tar -C /opt/temporal/1.32.2 -xzf temporal_1.32.2_linux_amd64.tar.gz \
  temporal-server temporal-sql-tool
(cd /opt/temporal/1.32.2 && sha256sum temporal-server temporal-sql-tool)   # harus sama dengan deploy/temporal/SOURCE.txt
# CLI operator 1.10.1 ke /opt/temporal/cli/temporal, sha256 juga di SOURCE.txt
sudo git clone <repo> /opt/deca-soar && cd /opt/deca-soar && git checkout <sha-yang-direview>
```

## 2. Database RDS (sebagai admin RDS, sekali)
```sql
CREATE ROLE temporal LOGIN PASSWORD '<dari vault ops>';
CREATE DATABASE temporal OWNER temporal;  CREATE DATABASE temporal_visibility OWNER temporal;

CREATE ROLE deca_owner LOGIN CREATEROLE PASSWORD '<…>';         -- hanya untuk migrasi
CREATE DATABASE deca_soar OWNER deca_owner;
-- setelah `deca-soar migrate` pertama membuat group role NOLOGIN:
CREATE ROLE deca_gw   LOGIN PASSWORD '<…>' IN ROLE deca_soar_gateway;
CREATE ROLE deca_brk  LOGIN PASSWORD '<…>' IN ROLE deca_soar_broker;
CREATE ROLE deca_aud  LOGIN PASSWORD '<…>' IN ROLE deca_soar_auditor;
```
Password tidak pernah masuk repo, chat atau log; hanya ke file secret di langkah 3.
Tidak ada aplikasi yang login sebagai `deca_owner`, jadi tidak ada proses yang bisa mengubah/menghapus ledger (F3).

## 3. Sertifikat dan secret (di ECS, bukan di repo/chat/log)
```sh
sudo install -d -m 0700 /etc/deca-soar/secrets
sudo install -d -m 0755 /etc/deca-soar/tls /etc/deca-soar/temporal/tls
sudo .venv/bin/python scripts/gen_secrets.py /etc/deca-soar/secrets
#   -> deca_tokenization_key, deca_vault_public_key, deca_vault_private_key, deca_temporal_payload_key (0600, tidak menimpa)
```
File secret lain (isi dari vault ops / PKI):

| File | Isi | Dipakai oleh |
|---|---|---|
| `secrets/temporal_db_password` | password user `temporal` | systemd LoadCredential |
| `secrets/deca_db_url_{owner,gateway,broker,auditor}` | `postgresql://<user>:<pw>@<rds>:5432/deca_soar?sslmode=verify-full&sslrootcert=…` | migrate / gateway / broker / anchor |
| `secrets/broker.key`, `tls/broker.pem`, `tls/broker-ca.pem` | TLS broker, SAN = nama privat broker | broker / worker |
| `temporal/tls/server.{pem,key}`, `server-ca.pem` | sertifikat frontend+internode, SAN = `temporal.deca.internal` | Temporal |
| `temporal/tls/client-ca.pem` | CA yang menandatangani sertifikat klien DECA saja | Temporal (requireClientAuth) |
| `temporal/tls/system-worker.{pem,key}` | sertifikat klien (dari client CA) untuk system worker internal Temporal | Temporal |
| `tls/temporal-server-ca.pem`, `tls/temporal-{gateway,worker}.pem`, `secrets/temporal-{gateway,worker}.key` | klien mTLS | gateway / worker |
| `rds-ca.pem` | CA RDS **[A]** | Temporal, DECA |

Backup terpisah dan wajib: `deca_vault_private_key`, `deca_tokenization_key`, `deca_temporal_payload_key`
(tanpa key, token PII dan history workflow tidak bisa dibuka). File yang dibaca uid 10001 di container: 0440 root:10001.

## 4. Temporal server (systemd)
```sh
sudo cp -r deploy/temporal/config deploy/temporal/dynamicconfig /etc/deca-soar/temporal/
sudo install -m 0640 -g temporal deploy/temporal/temporal.env.example /etc/deca-soar/temporal/temporal.env
# isi REPLACE_* : endpoint privat RDS, IP privat ECS (bukan 0.0.0.0)
.venv/bin/python scripts/preflight.py --temporal-bin /opt/temporal/1.32.2 \
  --temporal-env /etc/deca-soar/temporal/temporal.env            # harus "0 fail"
sudo cp deploy/temporal/systemd/*.service /etc/systemd/system/ && sudo systemctl daemon-reload
sudo systemctl enable --now temporal-server       # menjalankan temporal-schema (setup/upgrade skema) lebih dulu
TEMPORAL_ADDRESS=<ip-privat>:7233 TEMPORAL_TLS_CERT=<operator.pem> TEMPORAL_TLS_KEY=<operator.key> \
  TEMPORAL_TLS_CA=/etc/deca-soar/temporal/tls/server-ca.pem TEMPORAL_TLS_SERVER_NAME=temporal.deca.internal \
  deploy/temporal/bin/temporal-namespace.sh       # namespace deca-soar, retensi 30 hari
```
- Config menolak start tanpa mTLS, tanpa client CA, tanpa sertifikat system worker, atau dengan bind wildcard. Archival dan pprof mati.
- Tidak ada authorizer: **setiap pemegang sertifikat dari client CA DECA = admin Temporal.** Terbitkan hanya
  sertifikat gateway, worker dan operator; simpan key operator di bastion; cabut dengan mengganti client CA.
- Payload dan pesan error di history terenkripsi AES-256-GCM (key `deca_temporal_payload_key`), jadi operator
  Temporal tidak melihat isi alert atau keputusan.

## 5. DECA gateway + worker + broker (Docker compose)
```sh
docker build -f deploy/deca/Dockerfile -t deca-soar:$(git rev-parse --short HEAD) .   # ganti digest base image dulu
sudo install -m 0600 /dev/null /etc/deca-soar/deca.env   # DECA_SOAR_IMAGE, DECA_BIND_IP, DECA_TEMPORAL_ADDRESS,
                                                         # DECA_BROKER_URL=https://…:8100, DECA_POLICY_HOST_DIR, DECA_REPLAY_DIR
C="docker compose -f deploy/deca/docker-compose.yml --env-file /etc/deca-soar/deca.env"
$C run --rm deca-migrate                                 # buat group role (lalu langkah 2 bagian login user)
$C up -d broker
sudo install -d -m 0700 -o 10001 /etc/deca-soar/out
$C run --rm -v /etc/deca-soar/out:/out deca-migrate \
  deca-soar create-principal --name temporal-worker --kind service --role analyst --token-file /out/worker.token
# pindahkan worker.token → /etc/deca-soar/secrets/deca_broker_worker_token (0440 root:10001), hapus /etc/deca-soar/out
.venv/bin/python scripts/preflight.py --env /etc/deca-soar/deca.env --secrets-dir /etc/deca-soar/secrets
$C up -d gateway worker
sudo cp deploy/deca/systemd/deca-ledger-anchor.* /etc/systemd/system/ && sudo systemctl enable --now deca-ledger-anchor.timer
```
- `create-principal` memakai container `deca-migrate` karena hanya owner yang menulis `broker.principal`.
- `/etc/deca-soar/policy` = salinan `policy/` yang sudah direview; `protected.yaml` harus berisi IP/principal nyata
  (placeholder RFC5737 dihapus), kalau tidak broker menolak start di `DECA_ENV=production`.
- Approver = principal `human` role `approver`; service tidak pernah bisa approve atau kill switch.
- Fase 0 sumber gateway = replay file. Sumber SLS (RAM `soar-reader`) masuk Fase 1.
- Alur: gateway (inbox + tokenisasi) → start workflow `alert-<id>` → worker: triage (mock) → `POST /v1/actions/requests`
  ke broker → keputusan shadow + ledger. Bila Temporal mati, alert tetap di inbox gateway (retry + backoff, dead-letter
  setelah batas). Bila worker mati, workflow menunggu di Temporal dan jalan saat worker hidup. Error broker 5xx/429/
  jaringan di-retry hingga 24 jam; 4xx lain berhenti (tidak di-retry).

## 6. Verifikasi setelah deploy
1. `curl --cacert tls/broker-ca.pem https://<broker>:8100/healthz` dari ECS → `{"ok":true}`; dari luar SG → timeout.
2. `temporal operator cluster health` dengan sertifikat operator → `SERVING`; tanpa sertifikat → ditolak TLS.
3. Taruh 1 alert sintetis di `alerts.ndjson` → `temporal workflow describe -w alert-<id> -n deca-soar` = `COMPLETED`
   → `GET /v1/actions/requests/{id}` = `validated`, `mode=shadow`.
4. `deca-soar verify-ledger` (role auditor) → `ok: true`; `systemctl start deca-ledger-anchor` → exit 0.
5. `temporal workflow show -w alert-<id>` hanya menampilkan payload `binary/encrypted`, bukan IP/email.

## 7. Rollback
- Worker/gateway/broker: deploy image sha sebelumnya (`DECA_SOAR_IMAGE`). Workflow yang sedang jalan dilanjutkan
  worker lama selama nama workflow/activity sama; bila tidak kompatibel, kosongkan antrean dulu (`$C stop gateway`,
  tunggu workflow `RUNNING` = 0).
- Temporal: hentikan `temporal-server`, ganti `TEMPORAL_BIN_DIR` ke versi sebelumnya. Upgrade skema tidak bisa
  di-downgrade, jadi ambil snapshot RDS `temporal*` sebelum upgrade versi server.
- Migrasi DECA hanya menambah; ledger append-only tidak pernah di-rollback.
- Darurat: `deca-soar kill-switch on --principal <on-call>` (shadow tetap tercatat, aksi apa pun tidak dieksekusi).

## 8. Belum selesai di fase 0
- Compose/Dockerfile belum pernah dijalankan dengan Docker; digest base image masih placeholder.
- Temporal tanpa authorizer (lihat langkah 4); per-namespace authz butuh plugin authorizer sendiri (Fase 1).
- Anchor ledger ke file di host yang sama; sink SLS ada tapi belum diuji.
- LLM belum diuji (triage mock); egress per domain lewat proxy di Fase 1.
- Role break-glass (§6.9) dan Console approval belum dibuat; approval via API broker.
- **[A]** CA RDS, versi PostgreSQL RDS, aturan SG untuk port internode Temporal.
