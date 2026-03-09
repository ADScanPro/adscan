from __future__ import annotations

from typing import Any


def collect_workspace_variables_from_shell(shell: Any) -> dict[str, Any]:
    """Collect workspace-level variables from the CLI shell instance."""
    workspace_vars = {
        "hosts": getattr(shell, "hosts", None),
        "myip": getattr(shell, "myip", None),
        "interface": getattr(shell, "interface", None),
        "pdc": getattr(shell, "pdc", None),
        "pdc_hostname": getattr(shell, "pdc_hostname", None),
        "dcs": getattr(shell, "dcs", []),
        "domain": getattr(shell, "domain", None),
        "domains": getattr(shell, "domains", []),
        "username": getattr(shell, "username", None),
        "password": getattr(shell, "password", None),
        "hash": getattr(shell, "hash", None),
        "base_dn": getattr(shell, "base_dn", None),
        "dns": getattr(shell, "dns", None),
        "current_workspace": getattr(shell, "current_workspace", None),
        "current_workspace_dir": getattr(shell, "current_workspace_dir", None),
        "current_domain_dir": getattr(shell, "current_domain_dir", None),
        "domains_data": getattr(shell, "domains_data", {}),
        "neo4j_host": getattr(shell, "neo4j_host", "localhost"),
        "neo4j_port": getattr(shell, "neo4j_port", 7687),
        "neo4j_db_user": getattr(shell, "neo4j_db_user", "neo4j"),
        "neo4j_db_password": getattr(shell, "neo4j_db_password", "neo4j"),
        "auto": getattr(shell, "auto", False),
        "telemetry": getattr(shell, "telemetry", True),
        "type": getattr(shell, "type", None),
        "lab_provider": getattr(shell, "lab_provider", None),
        "lab_name": getattr(shell, "lab_name", None),
        "lab_name_whitelisted": getattr(shell, "lab_name_whitelisted", None),
        "lab_confirmation_state": getattr(shell, "lab_confirmation_state", None),
        "lab_inference_source": getattr(shell, "lab_inference_source", None),
        "lab_inference_confidence": getattr(shell, "lab_inference_confidence", None),
        "password_spraying_history": getattr(shell, "password_spraying_history", {}),
    }

    domains_data = workspace_vars.get("domains_data")
    if isinstance(domains_data, dict):
        sanitized = {}
        for domain_key, domain_data in domains_data.items():
            if isinstance(domain_data, dict):
                domain_data = dict(domain_data)
                domain_data.pop("credential_previews", None)
            sanitized[domain_key] = domain_data
        workspace_vars["domains_data"] = sanitized

    return workspace_vars


def collect_domain_variables_from_shell(shell: Any) -> dict[str, Any]:
    """Collect domain-level variables from the CLI shell instance."""
    domain = getattr(shell, "current_domain", None)
    variables: dict[str, Any] = {
        "hosts": getattr(shell, "hosts", None),
        "myip": getattr(shell, "myip", None),
        "interface": getattr(shell, "interface", None),
        "pdc": getattr(shell, "pdc", None),
        "pdc_hostname": getattr(shell, "pdc_hostname", None),
        "dcs": getattr(shell, "dcs", []),
        "domain": domain,
        "username": getattr(shell, "username", None),
        "password": getattr(shell, "password", None),
        "hash": getattr(shell, "hash", None),
        "base_dn": getattr(shell, "base_dn", None),
        "dns": getattr(shell, "dns", None),
        "current_workspace_dir": getattr(shell, "current_workspace_dir", None),
        "current_domain_dir": getattr(shell, "current_domain_dir", None),
    }

    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, dict) and domain and domain in domains_data:
        domain_entry = domains_data.get(domain)
        if isinstance(domain_entry, dict):
            variables.update(domain_entry)
    return variables


def apply_workspace_variables_to_shell(shell: Any, variables: dict[str, Any]) -> None:
    """Apply loaded workspace variables to the CLI shell instance."""
    defaults: dict[str, Any] = {
        "hosts": None,
        "myip": None,
        "interface": None,
        "pdc": None,
        "pdc_hostname": None,
        "dcs": [],
        "domain": None,
        "domains": [],
        "username": None,
        "password": None,
        "hash": None,
        "base_dn": None,
        "dns": None,
        "current_workspace": None,
        "current_workspace_dir": None,
        "current_domain": None,
        "current_domain_dir": None,
        "domains_data": {},
        "neo4j_host": "localhost",
        "neo4j_port": 7687,
        "neo4j_db_user": "neo4j",
        "neo4j_db_password": "neo4j",
        "auto": False,
        "telemetry": True,
        "type": None,
        "lab_provider": None,
        "lab_name": None,
        "lab_name_whitelisted": None,
        "lab_confirmation_state": None,
        "lab_inference_source": None,
        "lab_inference_confidence": None,
        "password_spraying_history": {},
    }

    for key, default in defaults.items():
        if key in variables:
            setattr(shell, key, variables.get(key))
        else:
            setattr(shell, key, default)

    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, dict):
        for _, domain_data in domains_data.items():
            if isinstance(domain_data, dict):
                domain_data.pop("credential_previews", None)


__all__ = [
    "apply_workspace_variables_to_shell",
    "collect_domain_variables_from_shell",
    "collect_workspace_variables_from_shell",
]
