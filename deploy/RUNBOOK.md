# Runbook deploy produksi — SOAR DECA Fase 0 (§12.2 tahap 1, shadow)

Status: **belum pernah dijalankan di Alibaba.** Compose belum dieksekusi dengan Docker (mesin build tanpa Docker);
yang sudah diuji adalah kode gateway/broker/ledger dan Tracecat 1.5.2 native di stack sekali pakai
(`.venv/bin/python e2e/run_e2e.py --evidence <dir-di-luar-repo>`; stack mati dan folder run dihapus di akhir).
Item bertanda **[A]** harus dicek di console Alibaba sebelum deploy.

## 0. Prasyarat (disiapkan owner/ops, bukan dari repo)
| Komponen | Isi |
|---|---|
| ECS-A (8 vCPU/16 GiB) | Tracecat; Docker + compose plugin; tanpa EIP |
| ECS-B (2 vCPU/4 GiB) | gateway + broker; tanpa EIP |
| RDS PostgreSQL | DB `tracecat`, `temporal`, `temporal_visibility`, `deca_soar`; user terpisah per DB; TLS on. **[A] pgvector + versi** |
| Tair | password + TLS (`rediss://`) **[A] TLS/port** |
| OSS | 5 bucket privat (attachments, registry, workflow, skills, agent); RAM user khusus bucket itu saja **[A] kompatibilitas S3 presigned URL** |
| Security group | ECS-A:8080 hanya dari proxy DECA; ECS-B:8100 hanya dari ECS-A; RDS/Tair hanya dari ECS-A/B |
| Egress | tidak ada internet keluar di fase 0, kecuali registry image (atau mirror ACR) |
| Proxy DECA | TLS + SSO di depan `https://soar.<domain-internal>` → ECS-A:8080 |

Tidak ada kredensial tulis Alibaba di mana pun. Broker menolak start bila `ALIBABA_CLOUD_ACCESS_KEY_*`,
`ALICLOUD_*` atau `DECA_SOAR_ACTOR_ROLE_ARN` ada di env.

## 1. Secret (di ECS, bukan di repo/chat/log)
```sh
sudo install -d -m 0700 /etc/deca-soar
sudo python3 scripts/gen_secrets.py /etc/deca-soar/secrets.env      # 4 secret platform + keyring + 2 key DECA
sudo cp deploy/tracecat/tracecat.env.example /etc/deca-soar/tracecat.env && sudo chmod 600 /etc/deca-soar/tracecat.env
# isi tracecat.env: salin nilai dari secrets.env, lalu RDS/Tair/OSS/IP dari console (password dari vault ops)
python3 scripts/preflight.py --env /etc/deca-soar/tracecat.env      # harus "0 fail"
```
Secret DECA (ECS-B) berupa file `/etc/deca-soar/secrets/{deca_db_url,deca_tokenization_key,deca_vault_key,deca_tracecat_webhook_url,deca_tracecat_webhook_api_key}`,
mode 0440 milik root:10001. `deca_vault_key` dan `deca_tokenization_key` wajib dibackup terpisah (tanpa key, token PII tidak bisa dibuka).

## 2. Tracecat (ECS-A)
```sh
cd deploy/tracecat
python3 ../../scripts/render_tracecat_compose.py --check            # artefak = hasil render dari upstream 1.5.2
docker compose --env-file /etc/deca-soar/tracecat.env -f docker-compose.prod.yml \
  -f upstream/docker-compose.sandbox.yml pull
docker compose --env-file /etc/deca-soar/tracecat.env -f docker-compose.prod.yml \
  -f upstream/docker-compose.sandbox.yml up -d
docker compose ... ps            # migrations exited 0; api/worker/executor/temporal healthy
```
- Overlay sandbox (nsjail) butuh executor privileged — **[A]** izinkan di ECS, atau jalankan tanpa overlay dan catat sebagai risiko.
- `ENTERPRISE_EDITION=false` dan `TRACECAT__FEATURE_FLAGS=` dipaksa oleh renderer.
- `agent-worker`, `agent-executor`, `litellm` **tidak dideploy**: runtime agent Tracecat (DurableAgentWorkflow,
  ApprovalManager/approval tool call) ada di paket `tracecat_ee` berlisensi Enterprise. Jangan pakai action `ai.*`.
- Setelah start pertama, Tracecat membangun artefak registry (~2 menit di uji lokal). Tunggu log api
  `Platform registry artifact build completed` sebelum menyalakan gateway: action yang jalan sebelumnya gagal
  dan alert-nya tidak dikirim ulang (gateway sudah menerima 2xx dari webhook).
- Bootstrap admin pertama: sementara `TRACECAT__AUTH_TYPES=basic` + `TRACECAT__AUTH_SUPERADMIN_EMAIL`, buat akun, aktifkan OIDC, lalu kembalikan ke `oidc` dan restart.
- Import workflow `tracecat/workflows/deca-alert-shadow.yml`, isi secret workspace `deca_broker` (`URL`, `TOKEN`), aktifkan webhook, buat API key webhook dan batasi IP webhook ke ECS-B; URL → file `deca_tracecat_webhook_url`, API key → `deca_tracecat_webhook_api_key` di ECS-B.

## 3. Gateway + broker (ECS-B)
```sh
docker build -f deploy/deca/Dockerfile -t deca-soar:$(git rev-parse --short HEAD) .   # ganti digest base image dulu
export DECA_SOAR_IMAGE=deca-soar:<sha> DECA_BIND_IP=<ip-privat-ECS-B> \
       DECA_POLICY_HOST_DIR=/etc/deca-soar/policy DECA_REPLAY_DIR=/var/lib/deca-soar/replay
docker compose -f deploy/deca/docker-compose.yml up -d deca-migrate broker gateway
sudo install -d -m 0700 -o 10001 /etc/deca-soar/out
docker compose -f deploy/deca/docker-compose.yml run --rm -v /etc/deca-soar/out:/out deca-migrate \
  deca-soar create-principal --name tracecat-svc --kind service --role analyst --token-file /out/tracecat-svc.token
# isi file token → secret Tracecat deca_broker.TOKEN, lalu hapus file-nya
```
- `/etc/deca-soar/policy` = salinan `policy/` yang sudah direview; `protected.yaml` harus berisi IP/principal nyata
  (placeholder RFC5737 dihapus), kalau tidak broker menolak start di `DECA_ENV=production`.
- Approver = principal `human` role `approver`; service tidak pernah bisa approve atau kill switch.
- Fase 0 sumber gateway = replay file. Sumber SLS (RAM `soar-reader`) masuk Fase 1.

## 4. Verifikasi setelah deploy
1. `curl http://<ECS-B>:8100/healthz` dari ECS-A → `{"ok":true}`; dari luar SG → timeout.
2. Taruh 1 alert sintetis di `alerts.ndjson` → run workflow sukses di Tracecat → `GET /v1/actions/requests/{id}` = `validated`, `mode=shadow`.
3. `deca-soar verify-ledger` → `ok: true`.
4. Cek DB Tracecat tidak berisi IP/email mentah dari alert (hanya `tok_*`).

## 5. Rollback
- Tracecat: `docker compose ... down` lalu `up -d` dengan tag sebelumnya; DB dipulihkan dari snapshot RDS/PITR bila migrasi gagal.
- Gateway/broker: deploy image sha sebelumnya. Migrasi DECA hanya menambah; ledger append-only tidak pernah di-rollback.
- Darurat: `deca-soar kill-switch on --principal <on-call>` (shadow tetap tercatat, aksi apa pun tidak dieksekusi).

## 6. Belum selesai di fase 0
- **Review lisensi (owner):** image Tracecat 1.5.2 memasang paket `tracecat-ee` sebagai dependensi wajib, dan
  worker DSL meng-import beberapa modul `tracecat_ee` saat start walau agent tidak dipakai. Perlu keputusan owner
  apakah ini dapat diterima untuk produksi, atau Tracecat diganti/di-fork tanpa paket itu.
- Role break-glass (§6.9) dan Console approval belum dibuat; approval via API broker.
- TLS antar ECS-A↔ECS-B (sekarang HTTP di VPC + bearer token) — rencana: Caddy/mTLS di ECS-B.
- LLM belum diuji (mock); egress per domain lewat proxy di Fase 1.
- Digest base image Dockerfile dan nama variabel TLS Temporal (`SQL_TLS_ENABLED`) **[A]**.
