# CIS Compliance Auditor — Backend Foundation

Starter backend for the team's MySQL persistence and configuration-drift work. It includes FastAPI, SQLAlchemy models for assets/audits/rules/findings/snapshots, asset and audit endpoints, and basic snapshot comparison.

## Requirements
- Python 3.11+
- MySQL 8+ (or use the SQLite development fallback temporarily)

## Windows PowerShell setup

```powershell
cd backend
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and set `DATABASE_URL`, for example:

```text
DATABASE_URL=mysql+pymysql://cis_user:YOUR_PASSWORD@localhost:3306/cis_auditor
```

Create the database once in MySQL Workbench or MySQL CLI:

```sql
CREATE DATABASE cis_auditor CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Then run:

```powershell
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs.

If MySQL is not ready yet, temporarily set `DATABASE_URL=sqlite:///./cis_auditor_dev.db` in `.env`. This is for local development only; switch back to MySQL for the persistence acceptance test.

## Endpoints
- `GET /api/assets`
- `POST /api/assets`
- `POST /api/audits`
- `GET /api/audits/{id}`
- `GET /api/audits/{id}/findings`
- `GET /api/audits/{id}/drift`

`POST /api/audits` accepts findings and an optional normalized snapshot. Example request:

```json
{
  "asset_id": 1,
  "status": "COMPLETED",
  "score": 75,
  "is_simulated": true,
  "findings": [
    {
      "rule_id": "NET-SSH-001",
      "status": "FAIL",
      "severity": "High",
      "expected": "Telnet disabled",
      "actual": "Telnet enabled",
      "evidence_source": "sample configuration fixture",
      "evidence": {"services": {"telnet": true}},
      "remediation": "Disable Telnet and use SSH for management"
    }
  ],
  "snapshot": {
    "is_simulated": true,
    "evidence": {"services": {"ssh": true, "telnet": true}, "logging": {"enabled": true}}
  }
}
```

Run a second audit for the same asset with changed snapshot evidence, then call `GET /api/audits/{second_audit_id}/drift`.

## Important limitations
- This is a persistence/API foundation, not a complete CIS evaluator or official benchmark mapping.
- The rule table is defined but rule CRUD and rule execution are not implemented here; coordinate those with the rule-engine owner.
- The drift endpoint compares snapshots for the same asset. Rule-to-setting correlation and newly failed/resolved control analysis are follow-up work.
- `Base.metadata.create_all` is suitable for this starter. Use migrations (e.g. Alembic) if the schema starts changing after real data exists.
