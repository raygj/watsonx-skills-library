# TFE Workspace Health Auditor - watsonx Orchestrate Integration

## Overview
This MCP server audits Terraform Enterprise workspace health — drift detection, Sentinel compliance, run health, and state integrity. It implements **Observe + Analyze (stages 5-6)** of the Instana-TFE-Vault Autonomic Loop.

Every finding emits a structured autonomic loop event tagged with its UHCCP layer and loop stage, consumable by Instana and Concert for closed-loop operations.

### UHCCP Layer Mapping
- **L4 Visibility** — run health, drift detection, state health
- **L5 Intelligence** — Sentinel compliance, module freshness, tag coverage, variable sets
- **L7 Learn** — autonomic loop events emitted for Concert/Instana consumption

## Prerequisites

1. **Python 3.11-3.13**
2. **Docker** (for watsonx Orchestrate Developer Edition)
3. **watsonx Orchestrate ADK**:
   ```bash
   pip install ibm-watsonx-orchestrate
   ```
4. **Terraform Enterprise** (or Terraform Cloud) with API access
5. **TFE API Token** with read access to workspaces, runs, policies, state

## Installation

### 1. Set Up Python Environment

```bash
cd skills/tfe-workspace-health
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Environment Variables

```bash
# Required
export TFE_ADDRESS=https://app.terraform.io  # or your TFE instance
export TFE_TOKEN=your-tfe-api-token

# Optional
export TFE_ORG=your-default-org
```

Required variables:
- `TFE_ADDRESS`: TFE instance URL (defaults to Terraform Cloud)
- `TFE_TOKEN`: TFE API token with read access

Optional:
- `TFE_ORG`: Default organization (can be overridden per call)

### 3. Test MCP Server Locally

```bash
# Run the MCP server
python server.py

# In another terminal, test with MCP inspector
mcp dev server.py
```

## Deploy to watsonx Orchestrate

### Option 1: Local Development (watsonx Orchestrate Developer Edition)

```bash
orchestrate toolkits import \
  --kind mcp \
  --name tfe-workspace-health \
  --description "Audit TFE workspace health with risk scoring and drift detection" \
  --package-root . \
  --language python \
  --command "python server.py" \
  -r requirements.txt

# Verify import
orchestrate toolkits list
```

### Option 2: Production Deployment

Create `watsonx_config.yaml`:

```yaml
kind: MCP
metadata:
  name: tfe-workspace-health
  description: TFE workspace health auditing with autonomic loop integration
spec:
  transport: stdio
  command: python
  args:
    - server.py
  env:
    - name: TFE_ADDRESS
      value: ${TFE_ADDRESS}
    - name: TFE_TOKEN
      valueFrom:
        secretKeyRef:
          name: tfe-credentials
          key: token
    - name: TFE_ORG
      value: ${TFE_ORG}
```

Deploy:
```bash
orchestrate toolkits import -f watsonx_config.yaml
```

## Create Agent Using the Skill

Create `agents/tfe_health_agent.yaml`:

```yaml
name: tfe-workspace-health-agent
description: "AI agent for TFE workspace health auditing and drift detection"
instructions: |
  You are a Terraform Enterprise infrastructure health expert. Your role is to:
  1. Audit workspace health across 7 dimensions (run health, Sentinel compliance,
     drift status, module freshness, tag coverage, variable sets, state health)
  2. Calculate risk scores based on production impact, compliance scope, and drift
  3. Generate prioritized remediation roadmaps (P0/P1/P2)
  4. Emit autonomic loop events for Instana/Concert consumption
  5. Explain findings in business terms (cost avoided, toil reduction)

  When responding:
  - Lead with business impact, not technical metrics
  - Reference compliance frameworks (OCC, PCI-DSS, SOX, NIST) when relevant
  - Prioritize production workspaces with drift or policy failures
  - Provide actionable next steps, not just data

model: ibm/granite-3.1-8b-instruct
tools:
  - tfe-workspace-health.audit_workspaces
resources:
  - tfe://compliance-rules
  - tfe://autonomic-loop-mapping
temperature: 0.3
max_tokens: 2000
```

Import agent:
```bash
orchestrate agents import -f agents/tfe_health_agent.yaml
```

## Usage Examples

### Example 1: Production Workspace Audit

```bash
User: "Audit all production workspaces in my-org"

Agent: [Calls audit_workspaces]
{
  "tfe_organization": "my-org",
  "workspace_filters": [{"type": "tag", "value": "env:production"}],
  "include_run_history": true,
  "include_drift_check": true
}

Response:
"I audited 24 production workspaces in my-org:
- 3 CRITICAL (immediate attention required)
- 7 HIGH (address within 30 days)
- 10 MEDIUM
- 4 LOW

Top priorities (P0):
1. prod-payments (risk: 10) — drift detected: 5 resources changed 12 days ago,
   Sentinel hard fail last week, PCI-DSS scope
2. prod-identity (risk: 9) — 45% run failure rate, no drift check in 14 days
3. prod-data-lake (risk: 9) — state file 230MB, missing required tags

Estimated impact: Addressing P0 workspaces avoids $180,000 in potential incident
costs and saves 52 hours of operational toil per quarter.

Would you like me to drill into any specific workspace?"
```

### Example 2: Drift Detection

```bash
User: "Which workspaces have drifted from their desired state?"

Agent: [Filters findings where drift_status check = fail]

Response:
"Found 6 workspaces with active drift:

Production (P0 — fix immediately):
1. prod-payments: 5 resources changed, 12 days old
2. prod-identity: 3 resources changed, 8 days old

Staging (P1 — fix within 30 days):
3. staging-api: 2 resources changed, 4 days old

Development (P2):
4. dev-sandbox: 1 resource changed, 1 day old

Compliance impact: OCC 2023-01 requires drift remediation within SLA.
PCI-DSS v4 Requirement 11.5 requires change integrity validation.

Recommended: Run targeted plans on prod-payments and prod-identity immediately."
```

### Example 3: Compliance Reporting

```bash
User: "Generate a compliance report for our SOX audit"

Agent: [Calls audit_workspaces + compliance-rules resource]

Response:
"SOX 404 IT General Controls Assessment — TFE Workspaces:

FINDING: 4 workspaces have Sentinel policy overrides (separation of duties concern)
- prod-payments: 2 overrides in last 30 days
- prod-identity: 1 override
CONTROL: SOX 404 Section — IT General Controls

FINDING: 7 workspaces missing required tags (audit trail incomplete)
- Missing: cost-center (5), data-classification (3)
CONTROL: SOX 404 — Audit Trail

FINDING: 2 workspaces with no drift check in 7+ days
CONTROL: SOX 404 — Change Management

Overall SOX Readiness: 67% (16/24 workspaces compliant)
Action Required: Address 8 non-compliant workspaces before audit window"
```

## Tool Reference

### `audit_workspaces` Tool

**Input Schema:**
```json
{
  "tfe_organization": "string (required)",
  "workspace_filters": [{"type": "name|tag", "value": "string"}],
  "include_run_history": true,
  "include_drift_check": true
}
```

**Output Schema:**
```json
{
  "total_workspaces": 24,
  "critical_count": 3,
  "high_count": 7,
  "medium_count": 10,
  "low_count": 4,
  "findings": [{
    "workspace_name": "prod-payments",
    "risk_score": 10,
    "risk_level": "critical",
    "checks": [{
      "check_name": "drift_status",
      "uhccp_layer": "L4 Visibility",
      "autonomic_stage": "stage-5-observe",
      "status": "fail",
      "detail": "...",
      "risk_points": 5
    }]
  }],
  "remediation_roadmap": {
    "P0_immediate": ["org/workspace (risk: 10)"],
    "P1_30_days": ["..."],
    "P2_90_days": ["..."]
  },
  "autonomic_loop_events": [{
    "event_id": "abc123",
    "autonomic_stage": "stage-5-observe",
    "severity": "critical",
    "summary": "[drift_status] Drift detected in production"
  }],
  "estimated_impact": {
    "potential_incident_cost_avoided": "$180,000",
    "workspaces_requiring_attention": 10,
    "estimated_toil_reduction_hours_per_quarter": 52
  }
}
```

## Risk Scoring Algorithm

**Per-Check Points (cumulative, capped at 10):**

| Factor | Condition | Points |
|--------|-----------|--------|
| Run failure rate | > 30% | +4 |
| Drift in production | detected | +5 |
| Sentinel hard fail | last 7 days | +3 |
| Module version | > 2 major behind | +3 |
| Missing required tags | any missing | +2 |
| No drift check | 7+ days | +2 |
| State file | > 100MB | +2 |
| Production env | yes | +2 |
| PCI/SOX scope | yes | +3 |

**Risk Levels:**
- CRITICAL: 9-10 points
- HIGH: 7-8 points
- MEDIUM: 4-6 points
- LOW: 1-3 points

## Integration with Other Skills

### Chaining with vault-secrets-auditor

```yaml
# Multi-skill agent workflow
agents:
  - name: infrastructure-health-automation
    steps:
      - tool: tfe-workspace-health.audit_workspaces
        output: workspace_health

      - tool: vault-secrets-auditor.audit_secrets
        output: secrets_health
        input:
          scan_targets:
            - type: vault_path
              location: secret/data/prod

      - description: "Correlate workspace drift with secret exposure"
        output: combined_risk_assessment
```

### Autonomic Loop Integration

```
Instana detects anomaly (stages 1-2)
  → Concert correlates across systems (stages 3-4)
    → tfe-workspace-health observes + analyzes (stages 5-6)  ← THIS SKILL
      → TFE remediates (stage 7, future skill)
        → Events feed back to Instana (stage 8)
```

## TFE API Endpoints Used (all read-only GET)

| Purpose | Endpoint |
|---------|----------|
| List workspaces | `GET /organizations/{org}/workspaces` |
| Get workspace | `GET /workspaces/{id}` |
| List runs | `GET /workspaces/{id}/runs` |
| Get policy checks | `GET /runs/{id}/policy-checks` |
| Current state version | `GET /workspaces/{id}/current-state-version` |
| Variable sets | `GET /workspaces/{id}/varsets` |
| Registry modules | `GET /organizations/{org}/registry-modules` |
| Auth check | `GET /account/details` |

## Troubleshooting

### TFE Connection Issues

```bash
# Test TFE connectivity
curl -s -H "Authorization: Bearer $TFE_TOKEN" \
  "$TFE_ADDRESS/api/v2/account/details" | jq .
```

### MCP Server Not Starting

```bash
# Check Python dependencies
pip list | grep -E "fastmcp|mcp|requests"

# Run with debug logging
export LOG_LEVEL=DEBUG
python server.py
```

### No Workspaces Found

```bash
# Verify org name and token permissions
curl -s -H "Authorization: Bearer $TFE_TOKEN" \
  "$TFE_ADDRESS/api/v2/organizations/$TFE_ORG/workspaces" | jq '.data | length'
```

---

**Skill Version**: 1.0.0
**Last Updated**: 2026-02-28
**Author**: Jim Ray

> **EXPERIMENTAL: NOT TESTED OR FOR PRODUCTION USE WITHOUT PROPER VALIDATION**
