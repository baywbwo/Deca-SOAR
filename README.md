# HyperSoar

HyperSoar (formerly DECA SOAR) is a shadow-first SOAR: an ingest gateway that normalises and tokenises
alerts, a Temporal worker that triages them, and an action broker that is the only holder of write
credentials and records every decision in an append-only hash-chained ledger.

- Python package `hypersoar`, CLI `hypersoar`, image `hypersoar:<git-sha>`, environment prefix `HYPERSOAR_`.
- Deployment: `deploy/RUNBOOK.md` (production), `deploy/lab/README.md` (lab).

## Identifiers kept from DECA SOAR

These names are stored state or crypto context, so renaming them would break existing installations.
They are internal and never shown to users.

| Identifier | Why it stays |
|---|---|
| DB `deca_soar`, roles `deca_soar_{gateway,broker,auditor,viewer}`, table `public.deca_schema_migrations`, migrate lock `deca_soar_migrate` | existing databases and grants |
| Vault HKDF info `deca-soar/vault/...` | existing sealed vault entries must still decrypt |
| Temporal namespace `deca-soar`, task queue `deca-soar-alerts` (overridable by env) | existing Temporal namespace |
| Host paths `/etc/deca-soar`, `/var/lib/deca-soar`, compose secret names `deca_*` | existing hosts; changed per host when re-provisioned |
