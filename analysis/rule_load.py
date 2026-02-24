# Loads YAML detection rules from the analysis/detection/rules/ directory.

import yaml
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def load_rules(rules_folder: str | Path) -> list[dict]:
    # Walk the folder recursively and pick up every .yml/.yaml file that has a 'title' key.
    rules = []
    rules_path = Path(rules_folder)

    if not rules_path.exists():
        logger.warning(f"Rules directory not found: {rules_path}")
        return rules

    for rule_file in sorted(rules_path.rglob("*.y*ml")):
        try:
            with open(rule_file, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if isinstance(data, dict) and data.get("title"):
                data["_file"] = str(rule_file)
                rules.append(data)
                logger.debug(f"Loaded rule: {data['title']}")
        except Exception as exc:
            logger.error(f"Failed to load rule {rule_file}: {exc}")

    logger.info(f"Loaded {len(rules)} detection rules from {rules_path}")
    return rules
