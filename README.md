# watsonx Skills Library

MCP skills for watsonx Orchestrate — enterprise infrastructure auditing and autonomic operations.

Each skill follows the same pattern: FastMCP server, risk scoring engine, compliance resource mapping, and structured output for agent consumption.

## Skills

| Skill | UHCCP Layers | Autonomic Loop Stages | Status |
|-------|-------------|----------------------|--------|
| [vault-secrets-auditor](skills/vault-secrets-auditor/) | L4 Visibility, L5 Intelligence | Observe + Analyze (secrets) | Production-ready |
| [tfe-workspace-health](skills/tfe-workspace-health/) | L4 Visibility, L5 Intelligence, L7 Learn | Observe + Analyze (stages 5-6) | New |

## Architecture

All skills implement stages of the **Instana-TFE-Vault Autonomic Loop** — the 8-stage closed-loop pattern for self-healing infrastructure:

```
Stage 1-2: Collect + Detect     (Instana)
Stage 3-4: Correlate + Decide   (Concert)
Stage 5-6: Observe + Analyze    (watsonx Skills)  <-- this library
Stage 7:   Act                  (TFE / Vault)
Stage 8:   Learn                (feedback loop)
```

Each skill emits **autonomic loop events** tagged with their stage, consumable by Instana and Concert for closed-loop operations.

## Quick Start

```bash
# Pick a skill
cd skills/vault-secrets-auditor

# Install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Configure and run
cp .env.example .env  # edit with your credentials
python server.py
```

## Deploying to watsonx Orchestrate

```bash
orchestrate toolkits import \
  --kind mcp \
  --name <skill-name> \
  --package-root skills/<skill-dir> \
  --language python \
  --command "python server.py" \
  -r requirements.txt
```

See each skill's README.md and DEPLOYMENT.md for full details.

## Contributing

Each skill lives in `skills/<skill-name>/` with:
- `server.py` — FastMCP server (single file, self-contained)
- `openapi.yaml` — OpenAPI spec for REST deployment
- `requirements.txt` — Python dependencies
- `README.md` — Integration guide
- `DEPLOYMENT.md` — Deployment patterns + demo script

---

**Maintained by:** IBM HashiCorp GTM Factory
**License:** Internal IBM use

> **EXPERIMENTAL: NOT TESTED OR FOR PRODUCTION USE WITHOUT PROPER VALIDATION**
