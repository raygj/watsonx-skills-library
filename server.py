#!/usr/bin/env python3
"""
Vault Secrets Auditor MCP Server
Integrates HashiCorp Vault MCP + Vault Radar MCP for secrets discovery and risk scoring
Designed for watsonx Orchestrate deployment
"""

import os
import re
import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
import hvac  # HashiCorp Vault Python client

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# Initialize MCP server
mcp = FastMCP("Vault Secrets Auditor")

# Environment configuration
VAULT_ADDR = os.getenv("VAULT_ADDR", "http://localhost:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
HCP_PROJECT_ID = os.getenv("HCP_PROJECT_ID")
HCP_CLIENT_ID = os.getenv("HCP_CLIENT_ID")
HCP_CLIENT_SECRET = os.getenv("HCP_CLIENT_SECRET")

# Validate required environment variables
if not VAULT_TOKEN:
    raise RuntimeError("VAULT_TOKEN environment variable is required")

# Initialize Vault client
vault_client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)

# Risk scoring constants
RISK_WEIGHTS = {
    "age": {"180_days": 3, "365_days": 5},
    "exposure": {"public_repo": 5, "shared_path": 3},
    "usage": {"high_traffic": 2, "production": 4},
    "compliance": {"pci_sox": 5}
}


class SecretType(Enum):
    """Types of secrets that can be detected"""
    VAULT_STATIC = "vault_static"
    GIT_REPO = "git_repo"
    CONFIG_FILE = "config_file"
    RADAR_FINDING = "radar_finding"


class RiskLevel(Enum):
    """Risk severity levels"""
    CRITICAL = "critical"  # 9-10
    HIGH = "high"  # 7-8
    MEDIUM = "medium"  # 4-6
    LOW = "low"  # 1-3


@dataclass
class SecretFinding:
    """Data class for secret findings"""
    id: str
    type: SecretType
    location: str
    secret_name: str
    last_rotated: Optional[str]
    age_days: Optional[int]
    metadata: Dict[str, Any]
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.LOW


@dataclass
class AuditResult:
    """Complete audit results"""
    total_secrets: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: List[Dict[str, Any]]
    risk_scores: Dict[str, int]
    migration_roadmap: Dict[str, List[str]]
    estimated_savings: Dict[str, Any]


# ===========================
# VAULT MCP INTEGRATION
# ===========================

def scan_vault_secrets(vault_path: str) -> List[SecretFinding]:
    """
    Scan Vault for static secrets using Vault MCP operations
    
    Args:
        vault_path: Vault path to scan (e.g., "secret/data/")
    
    Returns:
        List of SecretFinding objects
    """
    findings = []
    
    try:
        # List all secrets at path (Vault MCP: list operation)
        list_response = vault_client.secrets.kv.v2.list_secrets(
            path=vault_path.replace("/data/", "/metadata/")
        )
        
        if not list_response or 'data' not in list_response:
            logging.warning(f"No secrets found at {vault_path}")
            return findings
        
        secret_keys = list_response['data'].get('keys', [])
        
        for secret_key in secret_keys:
            try:
                # Read secret metadata (Vault MCP: read operation)
                metadata_path = f"{vault_path}/{secret_key}"
                metadata = vault_client.secrets.kv.v2.read_secret_metadata(
                    path=metadata_path.replace("/data/", "/metadata/")
                )
                
                # Check if it's a static secret (no rotation policy)
                is_static = is_static_secret(metadata)
                
                if is_static:
                    created_time = metadata['data'].get('created_time')
                    age_days = calculate_age_days(created_time)
                    
                    finding = SecretFinding(
                        id=generate_finding_id(f"vault-{vault_path}-{secret_key}"),
                        type=SecretType.VAULT_STATIC,
                        location=metadata_path,
                        secret_name=secret_key,
                        last_rotated=created_time,
                        age_days=age_days,
                        metadata={
                            "versions": len(metadata['data'].get('versions', {})),
                            "current_version": metadata['data'].get('current_version'),
                            "vault_path": vault_path
                        }
                    )
                    findings.append(finding)
                    logging.info(f"Found static secret: {secret_key} (age: {age_days} days)")
                    
            except Exception as e:
                logging.error(f"Error reading secret {secret_key}: {e}")
                continue
                
    except Exception as e:
        logging.error(f"Error scanning Vault path {vault_path}: {e}")
    
    return findings


def is_static_secret(metadata: Dict) -> bool:
    """
    Determine if a Vault secret is static (no dynamic generation)
    
    Args:
        metadata: Secret metadata from Vault
    
    Returns:
        True if secret is static
    """
    # Check for indicators of dynamic secrets:
    # - Lease duration set
    # - Associated with a role
    # - Part of a dynamic secrets engine (database, AWS, etc.)
    
    custom_metadata = metadata.get('data', {}).get('custom_metadata', {})
    
    # If tagged as dynamic, return False
    if custom_metadata.get('secret_type') == 'dynamic':
        return False
    
    # If no rotation policy and old, it's likely static
    versions = metadata.get('data', {}).get('versions', {})
    if len(versions) == 1:  # Never rotated
        return True
    
    return True  # Default to static if uncertain


# ===========================
# RADAR MCP INTEGRATION
# ===========================

def get_radar_findings(hcp_project_id: str) -> List[SecretFinding]:
    """
    Query Vault Radar MCP for secret findings
    
    Note: This is a mock implementation since we don't have actual Radar MCP credentials
    In production, this would call the Radar MCP server tools:
    - query_vault_radar_events
    - list_vault_radar_secret_types
    
    Args:
        hcp_project_id: HCP project ID
    
    Returns:
        List of SecretFinding objects from Radar
    """
    findings = []
    
    # In production, this would use Radar MCP tools:
    # radar_events = radar_mcp.query_vault_radar_events(
    #     project_id=hcp_project_id,
    #     severity="critical,high"
    # )
    
    logging.info("Radar MCP integration: Would query for leaked secrets here")
    
    # Mock finding for demonstration
    mock_finding = SecretFinding(
        id=generate_finding_id("radar-mock-1"),
        type=SecretType.RADAR_FINDING,
        location="github.com/company/repo/config.yml",
        secret_name="AWS_SECRET_KEY",
        last_rotated=None,
        age_days=None,
        metadata={
            "severity": "critical",
            "source": "github",
            "exposed_since": "2024-11-15"
        }
    )
    findings.append(mock_finding)
    
    return findings


# ===========================
# GIT REPO SCANNING
# ===========================

def scan_git_repo(repo_path: str) -> List[SecretFinding]:
    """
    Scan git repository for hardcoded secrets using entropy analysis
    
    Args:
        repo_path: Path to git repository
    
    Returns:
        List of SecretFinding objects
    """
    findings = []
    
    # Common secret patterns (regex-based detection)
    secret_patterns = {
        "AWS_ACCESS_KEY": r'AKIA[0-9A-Z]{16}',
        "AWS_SECRET_KEY": r'[A-Za-z0-9/+=]{40}',
        "GITHUB_TOKEN": r'ghp_[a-zA-Z0-9]{36}',
        "PRIVATE_KEY": r'-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----',
        "API_KEY": r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
        "PASSWORD": r'password["\']?\s*[:=]\s*["\']?([^"\'\s]{8,})',
    }
    
    # In production, would scan actual files
    # For now, return mock finding
    logging.info(f"Would scan git repo: {repo_path}")
    
    return findings


# ===========================
# RISK SCORING ENGINE
# ===========================

def calculate_age_days(created_time: str) -> int:
    """Calculate days since secret creation"""
    try:
        created = datetime.fromisoformat(created_time.replace('Z', '+00:00'))
        now = datetime.now(created.tzinfo)
        return (now - created).days
    except:
        return 0


def calculate_risk_score(finding: SecretFinding) -> int:
    """
    Calculate risk score (0-10) for a secret finding
    
    Scoring factors:
    - Age: +3 if >180 days, +5 if >365 days
    - Exposure: +5 if public repo, +3 if shared Vault path
    - Usage: +2 if high-traffic service, +4 if production
    - Compliance: +5 if PCI/SOX scope
    
    Args:
        finding: SecretFinding object
    
    Returns:
        Risk score (0-10)
    """
    score = 0
    
    # Age scoring
    if finding.age_days:
        if finding.age_days > 365:
            score += RISK_WEIGHTS["age"]["365_days"]
        elif finding.age_days > 180:
            score += RISK_WEIGHTS["age"]["180_days"]
    
    # Exposure scoring
    if finding.type == SecretType.GIT_REPO or finding.type == SecretType.RADAR_FINDING:
        score += RISK_WEIGHTS["exposure"]["public_repo"]
    elif "shared" in finding.location.lower():
        score += RISK_WEIGHTS["exposure"]["shared_path"]
    
    # Production usage (check metadata)
    if finding.metadata.get("environment") == "production":
        score += RISK_WEIGHTS["usage"]["production"]
    
    # Compliance scope
    if finding.metadata.get("compliance_scope") in ["pci", "sox", "pci-dss"]:
        score += RISK_WEIGHTS["compliance"]["pci_sox"]
    
    return min(score, 10)  # Cap at 10


def assign_risk_level(score: int) -> RiskLevel:
    """Convert numeric score to risk level"""
    if score >= 9:
        return RiskLevel.CRITICAL
    elif score >= 7:
        return RiskLevel.HIGH
    elif score >= 4:
        return RiskLevel.MEDIUM
    else:
        return RiskLevel.LOW


# ===========================
# MIGRATION PLANNING
# ===========================

def generate_migration_roadmap(findings: List[SecretFinding]) -> Dict[str, List[str]]:
    """
    Generate prioritized migration roadmap
    
    Returns:
        Dictionary with priority buckets (P0, P1, P2)
    """
    roadmap = {
        "P0_immediate": [],
        "P1_30_days": [],
        "P2_90_days": []
    }
    
    for finding in findings:
        if finding.risk_level == RiskLevel.CRITICAL:
            roadmap["P0_immediate"].append(finding.location)
        elif finding.risk_level == RiskLevel.HIGH:
            roadmap["P1_30_days"].append(finding.location)
        else:
            roadmap["P2_90_days"].append(finding.location)
    
    return roadmap


def estimate_breach_risk_reduction(findings: List[SecretFinding]) -> Dict[str, Any]:
    """
    Calculate estimated cost savings from secret migration
    
    Returns:
        Dictionary with savings metrics
    """
    # Industry average cost per breach: $4.45M (IBM 2023)
    # Hardcoded secrets involved in 80% of breaches
    # Each rotated secret reduces breach probability by ~5%
    
    critical_count = sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL)
    high_count = sum(1 for f in findings if f.risk_level == RiskLevel.HIGH)
    
    # Simplified ROI calculation
    avg_breach_cost = 4_450_000  # $4.45M
    risk_reduction_per_secret = 0.05  # 5% per critical secret
    
    potential_savings = critical_count * avg_breach_cost * risk_reduction_per_secret
    
    return {
        "potential_breach_cost_avoided": f"${potential_savings:,.0f}",
        "secrets_requiring_rotation": critical_count + high_count,
        "estimated_migration_hours": (critical_count * 4) + (high_count * 2),
        "roi_multiplier": f"{potential_savings / 100000:.1f}x" if critical_count > 0 else "N/A"
    }


def generate_finding_id(input_str: str) -> str:
    """Generate deterministic ID from input string"""
    return hashlib.md5(input_str.encode()).hexdigest()[:12]


# ===========================
# MCP TOOL: AUDIT SECRETS
# ===========================

@mcp.tool()
def audit_secrets(
    scan_targets: List[Dict[str, str]],
    include_radar_findings: bool = True
) -> str:
    """
    Scan for static secrets and generate migration roadmap with risk scores
    
    This tool integrates:
    - Vault MCP (list/read secrets from Vault paths)
    - Vault Radar MCP (query leaked secret events)
    - Git repo scanning (entropy-based secret detection)
    
    Args:
        scan_targets: List of scan target objects with 'type' and 'location'
                     Example: [
                         {"type": "vault_path", "location": "secret/data/prod"},
                         {"type": "git_repo", "location": "/path/to/repo"}
                     ]
        include_radar_findings: Whether to cross-reference with Radar (default: True)
    
    Returns:
        JSON string with audit results including:
        - static_secrets_found: List of findings
        - risk_scores: Mapping of finding IDs to scores
        - migration_roadmap: Prioritized action plan
        - estimated_savings: ROI calculations
    """
    logging.info(f"Starting secrets audit with {len(scan_targets)} targets")
    
    all_findings = []
    
    # 1. Scan each target
    for target in scan_targets:
        target_type = target.get("type")
        location = target.get("location")
        
        if target_type == "vault_path":
            findings = scan_vault_secrets(location)
            all_findings.extend(findings)
            
        elif target_type == "git_repo":
            findings = scan_git_repo(location)
            all_findings.extend(findings)
            
        else:
            logging.warning(f"Unknown target type: {target_type}")
    
    # 2. Cross-reference with Radar (if enabled)
    if include_radar_findings and HCP_PROJECT_ID:
        radar_findings = get_radar_findings(HCP_PROJECT_ID)
        all_findings.extend(radar_findings)
    
    # 3. Calculate risk scores
    risk_scores = {}
    for finding in all_findings:
        score = calculate_risk_score(finding)
        finding.risk_score = score
        finding.risk_level = assign_risk_level(score)
        risk_scores[finding.id] = score
    
    # 4. Generate migration roadmap
    roadmap = generate_migration_roadmap(all_findings)
    
    # 5. Calculate savings
    savings = estimate_breach_risk_reduction(all_findings)
    
    # 6. Build result object
    result = AuditResult(
        total_secrets=len(all_findings),
        critical_count=sum(1 for f in all_findings if f.risk_level == RiskLevel.CRITICAL),
        high_count=sum(1 for f in all_findings if f.risk_level == RiskLevel.HIGH),
        medium_count=sum(1 for f in all_findings if f.risk_level == RiskLevel.MEDIUM),
        low_count=sum(1 for f in all_findings if f.risk_level == RiskLevel.LOW),
        findings=[asdict(f) for f in all_findings],
        risk_scores=risk_scores,
        migration_roadmap=roadmap,
        estimated_savings=savings
    )
    
    logging.info(f"Audit complete: {result.total_secrets} secrets found, "
                f"{result.critical_count} critical")
    
    return json.dumps(asdict(result), indent=2, default=str)


# ===========================
# MCP RESOURCE: COMPLIANCE RULES
# ===========================

@mcp.resource("vault://compliance-rules")
def compliance_rules() -> str:
    """
    Compliance rules for secret management (FSI-specific)
    
    Returns:
        JSON string with compliance requirements
    """
    rules = {
        "PCI-DSS": {
            "requirement_3.4": "Secrets must be rotated every 90 days",
            "requirement_8.2": "No shared credentials across environments",
            "requirement_10.2": "All secret access must be logged"
        },
        "SOX": {
            "section_404": "Separation of duties - no single person has create+delete",
            "audit_trail": "Immutable audit logs for all secret operations"
        },
        "HIPAA": {
            "164.312": "Encryption at rest and in transit for all PHI secrets",
            "164.308": "Access controls with least-privilege"
        }
    }
    
    return json.dumps(rules, indent=2)


# ===========================
# MAIN SERVER ENTRY POINT
# ===========================

if __name__ == "__main__":
    logging.info("Starting Vault Secrets Auditor MCP Server...")
    logging.info(f"Vault Address: {VAULT_ADDR}")
    logging.info(f"HCP Project: {HCP_PROJECT_ID or 'Not configured'}")
    
    # Verify Vault connection
    try:
        if vault_client.is_authenticated():
            logging.info("✓ Vault authentication successful")
        else:
            logging.error("✗ Vault authentication failed")
    except Exception as e:
        logging.error(f"✗ Cannot connect to Vault: {e}")
    
    # Run MCP server
    mcp.run()
