"""
recommendation.py

Enterprise Recommendation Engine

Responsibilities
----------------
✔ Load scanner-specific rule databases
✔ Cache knowledge bases
✔ Return local recommendations
✔ Generate fallback recommendations
✔ Support every future scanner
✔ Safe error handling
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional

from security.common.logger import logger

############################################################
# Knowledge Directory
############################################################

KNOWLEDGE_DIR = Path("security/knowledge")

############################################################
# Framework Configuration
############################################################

FRAMEWORK_CONFIG = KNOWLEDGE_DIR / "framework_config.json"

_FRAMEWORK_CACHE: dict = {}

############################################################
# Rule Cache
############################################################

_RULE_CACHE: Dict[str, dict] = {}

############################################################
# Default Recommendation
############################################################

DEFAULT_RULE = {
    "title": "Security Finding",
    "description": "No description available.",
    "recommendation": "Review the finding manually.",
    "references": []
}

############################################################
# Load Rule Database
############################################################

def load_rule_database(scanner: str) -> dict:
    """
    Load scanner rule database.

    Uses in-memory cache for performance.
    """

    scanner = scanner.lower()

    if scanner in _RULE_CACHE:
        return _RULE_CACHE[scanner]

    rule_file = KNOWLEDGE_DIR / f"{scanner}_rules.json"

    if not rule_file.exists():

        logger.warning(
            f"No knowledge base found for scanner '{scanner}'."
        )

        _RULE_CACHE[scanner] = {}

        return {}

    try:

        with open(
            rule_file,
            "r",
            encoding="utf-8"
        ) as fp:

            rules = json.load(fp)

    except Exception as ex:

        logger.exception(
            f"Failed loading knowledge base: {rule_file}"
        )

        rules = {}

    _RULE_CACHE[scanner] = rules

    logger.info(
        f"Loaded {len(rules)} rules for {scanner}."
    )

    return rules

############################################################
# Framework Configuration Loader
############################################################

def load_framework_config() -> dict:
    """
    Load framework configuration.

    Cached after first load.
    """

    global _FRAMEWORK_CACHE

    if _FRAMEWORK_CACHE:
        return _FRAMEWORK_CACHE

    if not FRAMEWORK_CONFIG.exists():

        logger.warning(
            "framework_config.json not found."
        )

        return {}

    try:

        with open(
            FRAMEWORK_CONFIG,
            "r",
            encoding="utf-8"
        ) as fp:

            _FRAMEWORK_CACHE = json.load(fp)

    except Exception:

        logger.exception(
            "Unable to load framework_config.json"
        )

        _FRAMEWORK_CACHE = {}

    return _FRAMEWORK_CACHE

############################################################
# Local Recommendation Lookup
############################################################

def get_recommendation(
    scanner: str,
    rule_id: str | None,
) -> Optional[dict]:
    """
    Return local recommendation.

    Returns None when no local rule exists.
    """

    if not rule_id:
        return None

    rules = load_rule_database(scanner)

    return rules.get(rule_id)

############################################################
# Automatic Recommendation Builder
############################################################

def build_generic_recommendation(
    title: str | None = None,
    description: str | None = None,
    fixed_version: str | None = None,
    references: list | None = None,
) -> dict:
    """
    Automatically build a recommendation
    when no local knowledge exists.
    """

    config = load_framework_config()

    default_recommendation = config.get(
        "default_recommendation",
        "Review the finding manually."
    )

    default_reference = config.get(
        "default_reference"
    )

    if fixed_version:

        recommendation = (
            f"Upgrade to version {fixed_version} "
            "or later."
        )

    else:

        recommendation = default_recommendation

    if references:
        refs = references
    elif default_reference:
        refs = [default_reference]
    else:
        refs = []

    return {
        "title": title or "Security Finding",
        "description": description or "No description available.",
        "recommendation": recommendation,
        "references": refs
    }
############################################################
# Unified Recommendation API
############################################################

def resolve_recommendation(
    scanner: str,
    rule_id: str | None = None,
    title: str | None = None,
    description: str | None = None,
    fixed_version: str | None = None,
    references: list | None = None,
) -> dict:
    """
    Enterprise recommendation resolver.

    Priority:

        Local Knowledge Base
                ↓
        Generic Recommendation
                ↓
        Default Rule
    """

    local_rule = get_recommendation(
        scanner,
        rule_id,
    )

    if local_rule:

        return {
            "title": local_rule.get("title", title),
            "description": local_rule.get("description", description),
            "recommendation": local_rule.get("recommendation"),
            "references": local_rule.get("references", [])
        }

    generic = build_generic_recommendation(
        title=title,
        description=description,
        fixed_version=fixed_version,
        references=references,
    )

    return generic or DEFAULT_RULE

############################################################
# Cache Management
############################################################

def clear_cache() -> None:
    """
    Clear all cached knowledge bases.
    """

    global _FRAMEWORK_CACHE

    _RULE_CACHE.clear()

    _FRAMEWORK_CACHE = {}

    logger.info(
        "Knowledge cache cleared."
    )

############################################################
# Statistics
############################################################

def loaded_scanners() -> list[str]:
    """
    Return cached scanners.
    """

    return sorted(_RULE_CACHE.keys())

############################################################
# Manual Reload
############################################################

def reload_database(scanner: str) -> dict:
    """
    Force reload a scanner knowledge base.
    """

    scanner = scanner.lower()

    _RULE_CACHE.pop(scanner, None)

    return load_rule_database(scanner)
