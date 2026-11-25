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
| Security group | 7233 (Temporal frontend) dan 8100 (broker) hanya dari ECS ini + bastion operator; 7234/7235/6933–6939 hanya dari ECS ini; RDS hanya dari ECS ini. API HTTP frontend Temporal (7243) **mati** (`httpPort: 0`), jangan buka di SG |
| SLS terpisah | project `deca-soar-audit` milik tim security (bukan akun/project log aplikasi), logstore `ledger-anchor`, retensi ≥ 400 hari; machine group = ECS ini **[A]** |
| Vault ops | menyimpan DSN `deca_owner` (tidak pernah ada di ECS), password RDS, register penerbitan sertifikat client CA |
| Egress | tidak ada internet keluar di fase 0, kecuali registry image (atau mirror ACR) |
| PKI internal | CA server Temporal, CA broker, dan **client CA khusus Temporal** (kunci offline; lihat §4a) |

Tidak ada kredensial tulis Alibaba di mana pun. Broker dan worker menolak start bila `ALIBABA_CLOUD_ACCESS_KEY_*`,
`ALICLOUD_*` atau `HYPERSOAR_ACTOR_ROLE_ARN` ada di env. Worker juga menolak start bila memegang URL DB atau key vault.

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

CREATE ROLE deca_owner LOGIN CREATEROLE PASSWORD '<…>';         -- hanya untuk job owner, DSN di vault ops
CREATE DATABASE deca_soar OWNER deca_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;   -- (di DB deca_soar) default PG ≥ 15; PG lebih lama wajib, kalau tidak app menolak start
-- setelah `hypersoar migrate` pertama membuat group role NOLOGIN:
CREATE ROLE deca_gw   LOGIN PASSWORD '<…>' IN ROLE deca_soar_gateway;
CREATE ROLE deca_brk  LOGIN PASSWORD '<…>' IN ROLE deca_soar_broker;
CREATE ROLE deca_aud  LOGIN PASSWORD '<…>' IN ROLE deca_soar_auditor;
```
Password tidak pernah masuk repo, chat atau log; hanya ke file secret di langkah 3.
Tidak ada aplikasi yang login sebagai `deca_owner`, jadi tidak ada proses yang bisa mengubah/menghapus ledger (F3).
Login `deca_gw`/`deca_brk`/`deca_aud` jangan diberi atribut atau grant lain: broker, gateway dan job anchor mengecek
login DB-nya saat start dan **menolak jalan** bila login itu superuser/CREATEROLE/CREATEDB/BYPASSRLS/REPLICATION,
owner schema/tabel/DB, anggota role lain (termasuk `deca_owner`, `pg_read_all_data`), atau punya hak tabel/sequence/
schema di luar kebutuhan rolenya (review N4), punya grant per kolom di luar migrasi 0002/0003 (mis. `UPDATE(record)`
di `broker.decision_record`) atau `EXECUTE` pada fungsi di schema DECA / fungsi `SECURITY DEFINER` di `public` (N9).
Pesan error menyebut hak yang berlebih; perbaiki grant, jangan melonggarkan cek. Role aplikasi juga tidak bisa mengisi
`ledger.entry.seq` sendiri (N7, migrasi 0003).
**Jangan** memakai satu login admin/owner yang "diturunkan" lewat `options=-c role=…` di DSN atau `PGOPTIONS` (N8):
`RESET ROLE` mengembalikan hak login asli. Guard menolak bila `session_user` ≠ `current_user` (dan melaporkan atribut
login asli); preflight FAIL bila DSN aplikasi memuat `options` atau env memuat variabel `PG*`.

## 3. Sertifikat dan secret (di ECS, bukan di repo/chat/log)
```sh
sudo install -d -m 0700 /etc/deca-soar/secrets
sudo install -d -m 0755 /etc/deca-soar/tls /etc/deca-soar/temporal/tls
sudo .venv/bin/python scripts/gen_secrets.py /etc/deca-soar/secrets
#   -> deca_tokenization_key, deca_vault_public_key, deca_vault_private_key, deca_temporal_payload_key,
#      deca_integration_key, deca_source_key (0600, tidak menimpa)
# Instalasi lama (sebelum v0.9) yang sudah punya deca_integration_key: turunkan key sumber data untuk gateway
#   HYPERSOAR_INTEGRATION_KEY_FILE=/etc/deca-soar/secrets/deca_integration_key \
#     hypersoar integration derive-source-key --out /etc/deca-soar/secrets/deca_source_key
```
Gateway hanya memegang `deca_source_key` (subkey HKDF untuk secret SLS/webhook) dan menolak start bila diberi
`HYPERSOAR_INTEGRATION_KEY(_FILE)`. Master `deca_integration_key` hanya di broker.
File secret lain (isi dari vault ops / PKI):

| File | Isi | Dipakai oleh |
|---|---|---|
| `secrets/temporal_db_password` | password user `temporal` | systemd LoadCredential |
| `secrets/deca_db_url_{gateway,broker,auditor}` | `postgresql://<user>:<pw>@<rds>:5432/deca_soar?sslmode=verify-full&sslrootcert=…` | gateway / broker / anchor |
| ~~`secrets/deca_db_url_owner`~~ | **tidak disimpan di ECS** (N2): DSN owner tetap di vault ops, dipipe ke `deca-owner-run.sh` per job (§5) | migrate / create-principal |
| `secrets/broker.key`, `tls/broker.pem`, `tls/broker-ca.pem` | TLS broker, SAN = nama privat broker | broker / worker |
| `temporal/tls/server.{pem,key}`, `server-ca.pem` | sertifikat frontend+internode, SAN = `temporal.deca.internal` | Temporal |
| `temporal/tls/client-ca.pem` | client CA khusus Temporal, hanya sertifikat publiknya (kunci CA offline, §4a) | Temporal (requireClientAuth) |
| `temporal/tls/system-worker.{pem,key}` | sertifikat klien (dari client CA) untuk system worker internal Temporal | Temporal |
| `tls/temporal-server-ca.pem`, `tls/temporal-{gateway,worker}.pem`, `secrets/temporal-{gateway,worker}.key` | klien mTLS | gateway / worker |
| `rds-ca.pem` | CA RDS **[A]** | Temporal, DECA |

Backup terpisah dan wajib: `deca_vault_private_key`, `deca_tokenization_key`, `deca_temporal_payload_key`,
`deca_integration_key` (tanpa key, token PII, history workflow dan secret Lark/Jira/9router tidak bisa dibuka). File yang dibaca uid 10001 di container: 0440 root:10001.

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
- Tidak ada authorizer: **setiap pemegang sertifikat dari client CA = admin Temporal** (review N1). Fase 1 shadow
  boleh jalan dengan kontrol pengganti §4a; authorizer wajib sebelum kunci tulis / L1 auto.
- API HTTP frontend (port 7243) dimatikan di config (`httpPort: 0`, tidak bisa di-override env); preflight dan e2e
  membuktikan tidak ada listener HTTP (review N5). Operator hanya memakai gRPC 7233 + mTLS.
- Payload dan pesan error di history terenkripsi AES-256-GCM (key `deca_temporal_payload_key`), jadi operator
  Temporal tidak melihat isi alert atau keputusan.

### 4a. Kontrol pengganti authorizer Temporal (N1, wajib selama belum ada authorizer)
1. **Client CA khusus Temporal.** Tidak dipakai untuk TLS broker, Postgres atau server Temporal. Kunci privat CA
   offline (vault ops / HSM), **tidak pernah di ECS**.
2. **Hanya 4 sertifikat**: `temporal-gateway`, `temporal-worker`, `system-worker` (internal Temporal) dan
   `operator`. Setiap penerbitan (CN, serial, tanggal habis) dicatat di register vault ops; sertifikat lain = insiden.
3. **Masa berlaku ≤ 90 hari**, EKU `clientAuth` saja, bukan CA. Perpanjang sebelum habis; jadwalkan pengingat 14 hari.
4. **Kunci operator hanya di bastion** (0600, user operator), tidak di ECS dan laptop.
5. **SG 7233 hanya dari ECS ini + bastion [A]**; 7243 tidak dibuka (dan memang tidak listen).
6. **Pencabutan** = ganti client CA (Temporal tidak memeriksa CRL): terbitkan CA baru + 4 sertifikat, ganti
   `client-ca.pem`, restart `temporal-server`, lalu gateway/worker.

Cek di ECS (sertifikat operator dari bastion, bagian publik saja):
```sh
.venv/bin/python scripts/preflight.py --pki-root /etc/deca-soar --operator-cert <operator.pem>
#  FAIL bila: client CA = CA server/broker, sertifikat bukan dari client CA, bukan clientAuth, > 90 hari,
#  kedaluwarsa, atau kunci privat client CA ada di /etc/deca-soar. WARN berisi serial: cocokkan dengan register.
```
Yang tidak bisa dicek dari host: jumlah sertifikat yang pernah diterbitkan (register) dan aturan SG **[A]**.

## 5. DECA gateway + worker + broker (Docker compose)
```sh
# Base image dipin digest (N3): isi digest yang di-pull/di-scan, lalu build. Build berhenti bila masih placeholder.
docker pull python:3.12-slim-bookworm && docker inspect --format '{{index .RepoDigests 0}}' python:3.12-slim-bookworm
sudo install -m 0600 /dev/null /etc/deca-soar/deca.env   # HYPERSOAR_BASE_IMAGE=python:3.12-slim-bookworm@sha256:<64 hex>,
                                                         # HYPERSOAR_IMAGE, HYPERSOAR_BIND_IP, HYPERSOAR_TEMPORAL_ADDRESS,
                                                         # HYPERSOAR_BROKER_URL=https://…:8100, HYPERSOAR_POLICY_HOST_DIR
docker build -f deploy/deca/Dockerfile --build-arg BASE_IMAGE=<HYPERSOAR_BASE_IMAGE> -t hypersoar:$(git rev-parse --short HEAD) .
#   dependensi Python dari deploy/deca/requirements/*.lock (== + sha256, --require-hashes, wheel saja)
C="docker compose -f deploy/deca/docker-compose.yml --env-file /etc/deca-soar/deca.env"
O=deploy/deca/bin/deca-owner-run.sh                      # job owner: DSN dari stdin, file tmpfs 0400, dihapus saat selesai
<vault-ops get deca_db_url_owner> | sudo $O migrate      # buat group role (lalu langkah 2 bagian login user)
.venv/bin/python scripts/preflight.py --env /etc/deca-soar/deca.env --secrets-dir /etc/deca-soar/secrets \
  --pki-root /etc/deca-soar --operator-cert <operator.pem>   # harus "0 fail" (--env/--secrets-dir = mode produksi)
$C up -d broker                                          # menolak start bila login DB berlebih hak (N4)
sudo install -d -m 0700 -o 10001 /etc/deca-soar/out
<vault-ops get deca_db_url_owner> | sudo $O create-principal --name temporal-worker --kind service --role analyst \
  --token-file /out/worker.token
# pindahkan worker.token → /etc/deca-soar/secrets/deca_broker_worker_token (0440 root:10001), hapus /etc/deca-soar/out
$C up -d gateway worker
sudo cp deploy/deca/systemd/deca-ledger-anchor.* /etc/systemd/system/ && sudo systemctl enable --now deca-ledger-anchor.timer
```
- DSN owner **tidak pernah** jadi file di `/etc/deca-soar/secrets` (N2). `deca-owner-run.sh` membacanya dari stdin
  (prompt tersembunyi bila terminal), menulis ke `/dev/shm/deca-owner.XXXXXX/` (0400) hanya untuk satu
  `docker compose -f docker-compose.owner.yml run --rm owner-job`, lalu menghapusnya saat selesai, gagal atau di-Ctrl-C.
  Script menolak jalan bila `secrets/deca_db_url_owner` ada; preflight juga FAIL. `docker-compose.yml` tidak
  menyebut secret owner sama sekali, jadi `up` tidak pernah bisa menjalankan proses owner.
- Jangan taruh DSN di argumen atau `export`: masuk history shell / `ps`. Kalau DSN owner pernah tersimpan di host,
  hapus file lalu **rotasi password `deca_owner`**.
- **Setelah setiap owner job (N10)**: `sudo ls -d /dev/shm/deca-owner.* 2>/dev/null` harus kosong. `trap` tidak jalan
  bila skrip kena SIGKILL/OOM atau host mati, jadi direktori 0700 berisi DSN owner bisa tertinggal sampai reboot.
  Kalau ada: `sudo shred -u /dev/shm/deca-owner.*/deca_db_url_owner && sudo rmdir /dev/shm/deca-owner.*`, lalu
  **rotasi password `deca_owner`** di RDS dan vault ops, dan catat di log insiden. Selama ada sisa, `deca-owner-run.sh`
  menolak jalan (exit 65) dan preflight FAIL (`owner: no leftover owner DSN directory`).
- `/etc/deca-soar/policy` = salinan `policy/` yang sudah direview; `protected.yaml` harus berisi IP/principal nyata
  (placeholder RFC5737 dihapus), kalau tidak broker menolak start di `HYPERSOAR_ENV=production`.
- Approver = principal `human` role `approver`; service tidak pernah bisa approve atau kill switch.
- Fase 0 sumber gateway = replay file. Sumber SLS (RAM `soar-reader`) masuk Fase 1.
- Alur: gateway (inbox + tokenisasi) → start workflow `alert-<id>` → worker: triage (mock) → `POST /v1/actions/requests`
  ke broker → keputusan shadow + ledger. Bila Temporal mati, alert tetap di inbox gateway (retry + backoff, dead-letter
  setelah batas). Bila worker mati, workflow menunggu di Temporal dan jalan saat worker hidup. Error broker 5xx/429/
  jaringan di-retry hingga 24 jam; 4xx lain berhenti (tidak di-retry).

## 5b. Anchor ledger ke luar host (N2)
- `deca-ledger-anchor.timer` jalan **tiap jam** (menit 15): role auditor memverifikasi chain lalu menambah satu baris
  head ke `/var/lib/deca-soar/anchors/ledger-anchors.ndjson` (0600). Exit 1 = chain rusak / anchor lama tidak cocok.
- Logtail di ECS mengirim tiap baris baru ke SLS: buat config dari `deploy/deca/sls/ledger-anchor.logtail.yaml` di
  project audit terpisah **[A]**. Status: **belum diuji ke SLS**; fase 0 hanya membuktikan mekanismenya dengan
  pengirim mock di e2e (`n2_offhost_anchor_detects_root_rewrite`).
- Hak akses **[A]**: ECS hanya punya hak tulis Logtail (tidak bisa hapus/ubah logstore atau project); RAM user/role
  aplikasi SOAR tidak punya akses ke project audit. Admin project = tim security, bukan ops ECS.
- Cek independen (dari bastion/mesin security, bukan dari ECS yang dicurigai): ekspor logstore `ledger-anchor`
  (JSON / JSON lines; tiap item memakai field `content` = baris asli) lalu
  `hypersoar verify-ledger --anchors sls-export:<file-ekspor>` dengan DSN auditor → `ok: true`. Kalau ekspor kosong,
  verify gagal ("no anchored head"). Format ekspor SLS asli belum dicocokkan; sesuaikan reader bila beda.
- Root di ECS bisa menulis ulang ledger **dan** file anchor lokal; jendela yang belum ter-anchor ≤ 1 jam + jeda Logtail.

## 6. Verifikasi setelah deploy
1. `curl --cacert tls/broker-ca.pem https://<broker>:8100/healthz` dari ECS → `{"ok":true}`; dari luar SG → timeout.
2. `temporal operator cluster health` dengan sertifikat operator → `SERVING`; tanpa sertifikat → ditolak TLS.
3. Taruh 1 alert sintetis di `alerts.ndjson` → `temporal workflow describe -w alert-<id> -n deca-soar` = `COMPLETED`
   → `GET /v1/actions/requests/{id}` = `validated`, `mode=shadow`.
4. `hypersoar verify-ledger` (role auditor) → `ok: true`; `systemctl start deca-ledger-anchor` → exit 0; dalam beberapa
   menit baris anchor muncul di logstore SLS `ledger-anchor`, lalu `verify-ledger --anchors sls-export:<ekspor>` → `ok`.
5. `temporal workflow show -w alert-<id>` hanya menampilkan payload `binary/encrypted`, bukan IP/email.
6. `ss -ltnp` di ECS: Temporal hanya 7233/7234/7235/7239/6933–6939, **tidak ada 7243**; `ls /etc/deca-soar/secrets`
   tidak berisi `deca_db_url_owner`; `docker compose logs broker gateway` tidak berisi "refusing to start".
7. `preflight.py --env … --secrets-dir … --pki-root …` → `0 fail`; simpan output (tanpa secret) di bukti deploy.

## 7. Rollback
- Worker/gateway/broker: deploy image sha sebelumnya (`HYPERSOAR_IMAGE`). Workflow yang sedang jalan dilanjutkan
  worker lama selama nama workflow/activity sama; bila tidak kompatibel, kosongkan antrean dulu (`$C stop gateway`,
  tunggu workflow `RUNNING` = 0).
- Temporal: hentikan `temporal-server`, ganti `TEMPORAL_BIN_DIR` ke versi sebelumnya. Upgrade skema tidak bisa
  di-downgrade, jadi ambil snapshot RDS `temporal*` sebelum upgrade versi server.
- Migrasi DECA hanya menambah; ledger append-only tidak pernah di-rollback.
- Darurat: `hypersoar kill-switch on --principal <on-call> --reason "<alasan>"` (shadow tetap tercatat, aksi apa pun tidak dieksekusi).

## 8. Belum selesai di fase 0
- Compose/Dockerfile belum pernah dijalankan dengan Docker; digest base image diisi saat build (preflight produksi
  FAIL selama placeholder). Scan image (Trivy) + SBOM masuk bukti Fase 1.
- Temporal tanpa authorizer (N1): Fase 1 shadow memakai kontrol §4a; authorizer (ClaimMapper + Authorizer per CN)
  wajib sebelum kunci tulis / L1 auto.
- Logtail → SLS untuk anchor belum diuji di Alibaba (config siap, e2e pakai pengirim mock); format ekspor SLS belum
  dicocokkan. Sink `sls:` langsung dari aplikasi tetap tidak dipakai.
- Rotasi kunci payload Temporal (N6) belum didukung.
- LLM belum diuji (triage mock); egress per domain lewat proxy di Fase 1.
- Role break-glass (§6.9) dan Console approval belum dibuat; approval via API broker.
- **[A]** CA RDS, versi PostgreSQL RDS, aturan SG untuk port internode Temporal.
