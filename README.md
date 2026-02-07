                                                                                                                                             
.        .                              ,                     .   ..   
|_  _. __|_ * _. _ ._.._  ___ .    , _.-+- __ _ ._ \./ ___  __;_/*|| __
[ )(_]_) [ )|(_.(_)[  [_)      \/\/ (_] | _) (_)[ )/'\     _) | \|||_) 
                      |

# Vault Secrets Auditor - watsonx Orchestrate Integration

## Overview
This MCP server provides vault secrets auditing capabilities for watsonx Orchestrate, integrating HashiCorp Vault MCP and Vault Radar MCP for comprehensive secrets discovery and risk assessment.

## Prerequisites

1. **Python 3.11-3.13**
2. **Docker** (for watsonx Orchestrate Developer Edition)
3. **watsonx Orchestrate ADK**:
   ```bash
   pip install ibm-watsonx-orchestrate
   ```
4. **HashiCorp Vault** (running and accessible)
5. **HCP Vault Radar** (optional, for leaked secrets detection)

## Installation

### 1. Set Up Python Environment

```bash
cd vault_secrets_auditor
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Environment Variables

```bash
cp .env.example .env
# Edit .env with your credentials
```

Required variables:
- `VAULT_ADDR`: Your Vault server URL
- `VAULT_TOKEN`: Vault authentication token

Optional (for Radar integration):
- `HCP_PROJECT_ID`: HCP project ID
- `HCP_CLIENT_ID`: HCP service principal client ID
- `HCP_CLIENT_SECRET`: HCP service principal secret

### 3. Test MCP Server Locally

```bash
# Run the MCP server
python server.py
```

In another terminal:
```bash
# Test with MCP inspector
mcp dev server.py
```

## Deploy to watsonx Orchestrate

### Option 1: Local Development (watsonx Orchestrate Developer Edition)

```bash
# Import as MCP toolkit
orchestrate toolkits import \
  --kind mcp \
  --name vault-secrets-auditor \
  --description "Audit Vault secrets and generate migration roadmap" \
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
  name: vault-secrets-auditor
  description: Vault secrets auditing with risk scoring
spec:
  transport: stdio
  command: python
  args:
    - server.py
  env:
    - name: VAULT_ADDR
      value: ${VAULT_ADDR}
    - name: VAULT_TOKEN
      valueFrom:
        secretKeyRef:
          name: vault-credentials
          key: token
    - name: HCP_PROJECT_ID
      value: ${HCP_PROJECT_ID}
```

Deploy:
```bash
orchestrate toolkits import -f watsonx_config.yaml
```

## Create Agent Using the Skill

Create `agents/secrets_auditor_agent.yaml`:

```yaml
name: secrets-auditor-agent
description: "AI agent for vault secrets auditing and remediation planning"
instructions: |
  You are a HashiCorp Vault security expert. Your role is to:
  1. Audit Vault secrets for static credentials
  2. Cross-reference findings with Vault Radar leaked secrets
  3. Calculate risk scores based on age, exposure, and compliance requirements
  4. Generate prioritized migration roadmaps (P0/P1/P2)
  5. Provide ROI calculations for secret rotation initiatives
  
  When responding to queries:
  - Always explain risk scores in business terms
  - Prioritize findings by impact to production systems
  - Reference compliance frameworks (PCI-DSS, SOX, HIPAA) when relevant
  - Provide actionable next steps, not just data

model: ibm/granite-3.1-8b-instruct
tools:
  - vault-secrets-auditor.audit_secrets
resources:
  - vault://compliance-rules
temperature: 0.3  # Lower for consistent security analysis
max_tokens: 2000
```

Import agent:
```bash
orchestrate agents import -f agents/secrets_auditor_agent.yaml
```

## Usage Examples

### Example 1: Audit Production Secrets

```bash
# Via watsonx Orchestrate chat UI
User: "Audit all secrets in secret/data/prod and secret/data/shared"

Agent: [Calls audit_secrets tool]
{
  "scan_targets": [
    {"type": "vault_path", "location": "secret/data/prod"},
    {"type": "vault_path", "location": "secret/data/shared"}
  ],
  "include_radar_findings": true
}

Response:
"I found 47 static secrets across your production paths:
- 12 CRITICAL (immediate rotation required)
- 18 HIGH (rotate within 30 days)
- 17 MEDIUM (rotate within 90 days)

Top priorities (P0):
1. secret/data/prod/database-creds (365+ days old, PCI scope)
2. secret/data/shared/api-keys (exposed in Radar scan)
3. secret/data/prod/aws-keys (production environment)

Estimated breach cost avoided by rotating P0 secrets: $2,670,000
Migration effort: 48 hours

Would you like me to generate migration plans for the P0 secrets?"
```

### Example 2: Compliance Audit

```bash
User: "Show me all secrets that violate PCI-DSS 90-day rotation requirement"

Agent: [Filters findings where age_days > 90 AND compliance_scope = pci]

Response:
"Found 23 PCI-scoped secrets exceeding 90-day rotation policy:
- secret/data/prod/payment-gateway (187 days)
- secret/data/prod/cardholder-db (156 days)
...

Compliance risk: HIGH
Audit finding: Non-compliant with PCI-DSS Requirement 3.4

Recommended actions:
1. Immediate: Rotate all 23 secrets
2. Implement: Vault dynamic secrets for database credentials
3. Enforce: Automated rotation policies via Sentinel"
```

### Example 3: Cross-Platform Detection

```bash
User: "Check for secrets leaked to GitHub that also exist in Vault"

Agent: [Calls audit_secrets with git_repo targets + Radar findings]

Response:
"Radar detected 3 secrets from your Vault in public repositories:

1. AWS_ACCESS_KEY (AKIA...R7Q)
   - Found in: github.com/company/terraform-configs/main.tf
   - Also exists in: secret/data/prod/aws-creds
   - Risk: CRITICAL (public exposure + production use)
   - Action: Rotate immediately in Vault + revoke leaked key in AWS

2. Database password
   - Found in: github.com/company/api/config.yaml
   - Matches: secret/data/prod/postgres
   - Risk: CRITICAL
   - Action: Rotate + implement dynamic secrets

Estimated incident response cost if exploited: $4.2M
Estimated fix time: 6 hours"
```

## Tool Reference

### `audit_secrets` Tool

**Input Schema:**
```json
{
  "scan_targets": [
    {
      "type": "vault_path|git_repo|config_file",
      "location": "string"
    }
  ],
  "include_radar_findings": boolean
}
```

**Output Schema:**
```json
{
  "total_secrets": int,
  "critical_count": int,
  "high_count": int,
  "medium_count": int,
  "low_count": int,
  "findings": [
    {
      "id": "string",
      "type": "vault_static|git_repo|radar_finding",
      "location": "string",
      "secret_name": "string",
      "age_days": int,
      "risk_score": 0-10,
      "risk_level": "critical|high|medium|low",
      "metadata": {}
    }
  ],
  "risk_scores": {"finding_id": score},
  "migration_roadmap": {
    "P0_immediate": ["path1", "path2"],
    "P1_30_days": ["path3"],
    "P2_90_days": ["path4"]
  },
  "estimated_savings": {
    "potential_breach_cost_avoided": "$X",
    "secrets_requiring_rotation": int,
    "estimated_migration_hours": int
  }
}
```

## Risk Scoring Algorithm

**Factors:**
- **Age**: +3 if >180 days, +5 if >365 days
- **Exposure**: +5 if public repo, +3 if shared Vault path
- **Usage**: +2 if high-traffic, +4 if production
- **Compliance**: +5 if PCI/SOX scope

**Risk Levels:**
- CRITICAL: 9-10 points
- HIGH: 7-8 points
- MEDIUM: 4-6 points
- LOW: 1-3 points

## Integration with Other Skills

### Chaining with static-to-dynamic-migrator

```yaml
# Multi-step agent workflow
agents:
  - name: secrets-lifecycle-automation
    steps:
      - tool: vault-secrets-auditor.audit_secrets
        output: audit_results
      
      - condition: audit_results.critical_count > 0
        tool: static-to-dynamic-migrator.migrate_secret
        input:
          secret_type: database
          target_system: ${audit_results.findings[0].location}
      
      - tool: vault-policy-reviewer.review_vault_policy
        description: "Ensure new dynamic secrets have proper policies"
```

## Troubleshooting

### Vault Connection Issues

```bash
# Test Vault connectivity
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=hvs.YOUR_TOKEN
vault status
```

### MCP Server Not Starting

```bash
# Check Python dependencies
pip list | grep -E "fastmcp|mcp|hvac"

# Run with debug logging
export LOG_LEVEL=DEBUG
python server.py
```

### Radar Integration Not Working

```bash
# Verify HCP credentials
echo $HCP_PROJECT_ID
echo $HCP_CLIENT_ID

# Test Radar MCP separately
docker run --rm -i \
  -e HCP_PROJECT_ID=$HCP_PROJECT_ID \
  -e HCP_CLIENT_ID=$HCP_CLIENT_ID \
  -e HCP_CLIENT_SECRET=$HCP_CLIENT_SECRET \
  hashicorp/vault-radar-mcp-server:latest
```

## Production Considerations

1. **Secrets Management**: Never commit `.env` with real credentials. Use watsonx Orchestrate's credential vault.

2. **Rate Limiting**: Vault MCP calls are rate-limited. For large-scale scans (1000+ secrets), implement batching:
   ```python
   # In production code
   BATCH_SIZE = 100
   for batch in chunks(secret_paths, BATCH_SIZE):
       findings.extend(scan_vault_secrets(batch))
       time.sleep(1)  # Rate limit protection
   ```

3. **Caching**: Audit results can be cached for 1 hour to reduce Vault API load:
   ```python
   @mcp.tool(cache_ttl=3600)
   def audit_secrets(...):
       ...
   ```

4. **Monitoring**: Enable metrics export for watsonx Orchestrate monitoring:
   ```yaml
   metrics:
     enabled: true
     endpoint: /metrics
   ```

## Next Steps

1. **Deploy skill #5** (vault-policy-reviewer) for PR review automation
2. **Deploy skill #6** (static-to-dynamic-migrator) for remediation workflows
3. **Build Project Bob integration** for IDE-based secret detection

## Resources

- [watsonx Orchestrate ADK Documentation](https://developer.watson-orchestrate.ibm.com)
- [Vault MCP Server](https://developer.hashicorp.com/vault/docs/mcp-server)
- [Radar MCP Server](https://developer.hashicorp.com/hcp/docs/vault-radar/mcp-server)
- [FastMCP Python SDK](https://github.com/jlowin/fastmcp)

---

**Skill Version**: 1.0.0  
**Last Updated**: 2026-02-06  
**Author**: IBM HashiCorp GTM Factory
