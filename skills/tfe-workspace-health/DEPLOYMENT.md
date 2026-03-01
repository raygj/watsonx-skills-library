# TFE Workspace Health Auditor - Deployment Package

## What I Built

**Skill: tfe-workspace-health** - MCP server for watsonx Orchestrate

### Core Capabilities
1. **7 Health Checks**: Run health, Sentinel compliance, drift detection, module freshness, tag coverage, variable set completeness, state health
2. **Risk Scoring Engine**: 0-10 scale based on drift, failures, compliance scope, production context
3. **Autonomic Loop Events**: Structured events tagged with UHCCP layer and loop stage for Instana/Concert
4. **Compliance Mapping**: OCC, FFIEC, DORA, PCI-DSS, SOX 404, NIST 800-53
5. **Business Impact**: Cost avoidance and toil reduction estimates in business language

### Implementation Details

**Technology Stack:**
- `fastmcp`: MCP server framework
- `requests`: TFE API client (read-only GET operations)
- `python-dotenv`: Environment configuration
- Python 3.11+

**Architecture Pattern:**
```
watsonx Orchestrate Agent
    ↓ (calls MCP tool)
tfe-workspace-health MCP Server
    ↓ (read-only API calls)
Terraform Enterprise API
    ├── /workspaces        (list, get)
    ├── /runs              (list, policy checks)
    ├── /state-versions    (current state)
    ├── /varsets            (variable sets)
    └── /registry-modules  (module versions)
```

**UHCCP Anchor:**
```
Instana (L1-L3)  →  Concert (L4 decision)  →  This Skill (L4-L5 observe+analyze)  →  TFE (L6 act)
     stages 1-2          stages 3-4                   stages 5-6                      stage 7
```

**Files Created:**
```
skills/tfe-workspace-health/
├── server.py              # Main MCP server (~600 lines)
├── requirements.txt       # Python dependencies
├── openapi.yaml           # OpenAPI spec for REST API deployment
├── README.md              # Full integration guide
└── DEPLOYMENT.md          # This file
```

## Key Features

### 1. Risk Scoring Algorithm
```
Per-Check Points (cumulative, capped at 10):
- Run failure rate > 30%:     +4
- Drift in production:        +5
- Sentinel hard fail (7d):    +3
- Module > 2 major behind:    +3
- Missing required tags:      +2
- No drift check 7+ days:     +2
- State file > 100MB:         +2
- Production environment:     +2
- PCI/SOX scope:              +3

Output: 0-10 score → CRITICAL/HIGH/MEDIUM/LOW
```

### 2. Autonomic Loop Events
Every failed or warned check emits a structured event:
```json
{
  "event_id": "deterministic-hash",
  "timestamp": "2026-02-28T12:00:00Z",
  "autonomic_stage": "stage-5-observe",
  "uhccp_layer": "L4 Visibility",
  "workspace": "prod-payments",
  "organization": "my-org",
  "severity": "critical",
  "summary": "[drift_status] Drift detected in production: 5 resources changed",
  "detail": {"drift_detected": true, "resources_drifted": 5, "drift_age_days": 12}
}
```

### 3. Business-Language Impact
```json
{
  "potential_incident_cost_avoided": "$180,000",
  "workspaces_requiring_attention": 10,
  "estimated_toil_reduction_hours_per_quarter": 52,
  "business_summary": "3 workspaces at critical risk, 7 at high risk. Addressing these avoids..."
}
```

## Deployment Options

### Option 1: watsonx Orchestrate Developer Edition (Recommended for Testing)

```bash
# 1. Install dependencies
cd skills/tfe-workspace-health
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Configure TFE credentials
export TFE_ADDRESS=https://app.terraform.io
export TFE_TOKEN=your-token
export TFE_ORG=your-org

# 3. Import to watsonx Orchestrate
orchestrate toolkits import \
  --kind mcp \
  --name tfe-workspace-health \
  --description "Audit TFE workspace health with risk scoring" \
  --package-root . \
  --language python \
  --command "python server.py" \
  -r requirements.txt

# 4. Create agent
orchestrate agents import -f agents/tfe_health_agent.yaml
```

### Option 2: Production (Containerized)

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .
EXPOSE 8000
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
```

Then import via OpenAPI spec:
```bash
orchestrate toolkits import \
  --kind openapi \
  --name tfe-workspace-health \
  --spec openapi.yaml \
  --url https://tfe-health.your-domain.com
```

## Demo Script for Advanced SAs

### Setup (5 min)
1. Set TFE credentials for a demo org with 10+ workspaces
2. Ensure some workspaces have:
   - Recent run failures
   - Missing tags
   - Old state files
3. Start MCP server: `python server.py`

### Demo Flow (10 min)

**Scene 1: Workspace Health Audit**
```
SA: "I need to audit our production Terraform workspaces for operational risk"

Agent: [Calls audit_workspaces]
"I audited 24 production workspaces in your organization:

3 CRITICAL — immediate attention:
1. prod-payments (risk: 10) — drift detected, Sentinel hard fail, PCI scope
2. prod-identity (risk: 9) — 45% run failure rate, no drift check in 14 days
3. prod-data-lake (risk: 9) — 230MB state file, missing required tags

7 HIGH — address within 30 days
10 MEDIUM, 4 LOW

Estimated impact: Addressing critical workspaces avoids $180,000 in potential
incident costs and saves 52 hours of operational toil per quarter."
```

**Scene 2: Drift Detection**
```
SA: "Show me which production workspaces have drifted"

Agent: [Filters drift_status checks]
"2 production workspaces have active drift:

1. prod-payments: 5 resources changed, 12 days ago
   - Risk: CRITICAL (production + PCI scope)
   - OCC 2023-01 requires remediation within SLA

2. prod-identity: 3 resources changed, 8 days ago
   - Risk: CRITICAL (production + SOX scope)

Recommended: Run targeted terraform plan on both workspaces to validate
drift, then apply with Sentinel policy check."
```

**Scene 3: Compliance Reporting**
```
SA: "Generate a compliance report for our quarterly SOX review"

Agent: [Combines audit results + compliance-rules resource]
"SOX 404 Compliance Assessment — TFE Infrastructure:

Compliant: 16/24 workspaces (67%)
Non-compliant: 8 workspaces

Key Findings:
1. Separation of Duties: 4 workspaces with Sentinel overrides
2. Audit Trail: 7 workspaces missing cost-center or data-classification tags
3. Change Management: 2 workspaces with no drift check in 7+ days

Autonomic Loop: 15 events emitted for Concert/Instana correlation.
These events close the loop between infrastructure observation and
organizational compliance reporting."
```

**Key Demo Points:**
- Real-time TFE API integration (not mock data)
- Business-focused language (cost avoided, toil reduction)
- Compliance mapping (OCC, PCI, SOX, NIST)
- Autonomic loop events for Instana/Concert
- Actionable remediation roadmap (P0/P1/P2)

## Testing Checklist

- [ ] TFE connection successful (`/account/details`)
- [ ] MCP server starts (`python server.py`)
- [ ] Tool import to watsonx Orchestrate succeeds
- [ ] Agent can call `audit_workspaces` tool
- [ ] Risk scoring produces expected results
- [ ] Remediation roadmap prioritization correct
- [ ] Compliance rules resource accessible
- [ ] Autonomic loop mapping resource accessible
- [ ] Events emitted for failed/warned checks

## What's NOT Built (Future Work)

1. **Act Stage (Stage 7)**: This skill observes and analyzes only — never remediates
   - Future: auto-run `terraform plan` for drift remediation
   - Future: auto-apply with approval gate

2. **HCL Parsing**: Module freshness check currently relies on registry metadata
   - Future: parse workspace Terraform config to compare module versions

3. **Real-Time Streaming**: Currently point-in-time audit
   - Future: WebSocket stream of autonomic events to Instana

4. **Multi-Org**: Currently scans one org per call
   - Future: cross-org correlation for enterprise-wide view

## Performance Considerations

- Each workspace requires 3-5 API calls (runs, policy checks, state, varsets)
- For 100+ workspaces, expect 30-60 seconds (TFE API rate limits)
- Sentinel policy checks are the heaviest call (one per run)
- Consider filtering to production workspaces for faster scans

## Security Considerations

1. **TFE Token**: Read-only access required — never write/delete
2. **API Surface**: All operations are GET requests — no mutation
3. **Token Storage**: Use watsonx Orchestrate credential vault, never commit tokens
4. **Audit Logging**: All API calls logged for compliance

---

**Built by:** IBM HashiCorp GTM Factory
**Version:** 1.0.0
**Status:** New

> **EXPERIMENTAL: NOT TESTED OR FOR PRODUCTION USE WITHOUT PROPER VALIDATION**
