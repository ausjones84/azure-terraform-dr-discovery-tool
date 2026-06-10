"""
drift_parser.py - Drift CSV / Candidates File Parser
=====================================================
Parses existing drift_candidates.csv or drift.csv files and
integrates findings into the comparison engine.

SAFETY: Read-only. Never modifies drift files.
"""

import csv
import logging
from pathlib import Path
from typing import List, Optional

from models import DriftEntry

logger = logging.getLogger(__name__)

# Common column name aliases for flexible CSV support
RESOURCE_NAME_COLS = {"resource_name", "name", "resource", "azure_resource_name"}
RESOURCE_TYPE_COLS = {"resource_type", "type", "azure_resource_type"}
RESOURCE_GROUP_COLS = {"resource_group", "rg", "resourcegroup", "resource_group_name"}
SUBSCRIPTION_COLS = {"subscription_id", "subscription", "sub_id", "subscriptionid"}
STATUS_COLS = {"status", "drift_status", "comparison_status", "state"}
NOTES_COLS = {"notes", "note", "comments", "comment", "description", "details"}


def _normalize_header(header: str) -> str:
    """Normalize column header to lowercase stripped."""
    return header.strip().lower().replace(" ", "_").replace("-", "_")


def _find_col(headers: List[str], candidates: set) -> Optional[int]:
    """Find the first matching column index from a set of candidate names."""
    for i, h in enumerate(headers):
        if _normalize_header(h) in candidates:
            return i
    return None


def parse_drift_file(file_path: str) -> List[DriftEntry]:
    """
    Parse a drift CSV file (drift.csv or drift_candidates.csv).

    Accepts flexible column naming. Required columns (by common aliases):
    - resource_name / name / resource
    - resource_type / type (optional)
    - resource_group / rg (optional)
    - status / drift_status (optional)
    - notes / comments (optional)

    Args:
        file_path: Path to the drift CSV file.

    Returns:
        List of DriftEntry objects parsed from the file.
    """
    entries: List[DriftEntry] = []
    path = Path(file_path)

    if not path.exists():
        logger.warning("Drift file not found: %s", file_path)
        return entries

    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as csvfile:
            reader = csv.reader(csvfile)
            raw_headers = next(reader, None)
            if not raw_headers:
                logger.warning("Drift file is empty: %s", file_path)
                return entries

            headers = [h.strip() for h in raw_headers]

            # Map columns
            name_idx = _find_col(headers, RESOURCE_NAME_COLS)
            type_idx = _find_col(headers, RESOURCE_TYPE_COLS)
            rg_idx = _find_col(headers, RESOURCE_GROUP_COLS)
            sub_idx = _find_col(headers, SUBSCRIPTION_COLS)
            status_idx = _find_col(headers, STATUS_COLS)
            notes_idx = _find_col(headers, NOTES_COLS)

            if name_idx is None:
                logger.error(
                    "Cannot find resource name column in %s. "
                    "Expected one of: %s. Found: %s",
                    file_path,
                    RESOURCE_NAME_COLS,
                    headers,
                )
                return entries

            for row in reader:
                if not row or all(c.strip() == "" for c in row):
                    continue  # Skip blank rows

                def _get(idx: Optional[int], default: str = "") -> str:
                    if idx is None or idx >= len(row):
                        return default
                    return row[idx].strip()

                entry = DriftEntry(
                    resource_name=_get(name_idx),
                    resource_type=_get(type_idx),
                    resource_group=_get(rg_idx),
                    subscription_id=_get(sub_idx),
                    status=_get(status_idx),
                    notes=_get(notes_idx),
                    raw_row=dict(zip(headers, row)),
                )

                if not entry.resource_name:
                    logger.debug("Skipping row with empty resource name: %s", row)
                    continue

                entries.append(entry)

        logger.info("Parsed %d drift entries from %s", len(entries), file_path)

    except csv.Error as exc:
        logger.error("CSV parsing error in %s: %s", file_path, exc)
    except OSError as exc:
        logger.error("File read error for %s: %s", file_path, exc)

    return entries


def find_drift_files(search_roots: List[str]) -> List[str]:
    """
    Recursively search for drift CSV files in the given directories.

    Looks for: drift.csv, drift_candidates.csv, *drift*.csv

    Args:
        search_roots: List of directory paths to search.

    Returns:
        List of found drift file paths.
    """
    found = []
    for root in search_roots:
        root_path = Path(root)
        if not root_path.exists():
            continue
        for pattern in ["drift.csv", "drift_candidates.csv", "*drift*.csv", "*_drift.csv"]:
            for match in root_path.rglob(pattern):
                if match.is_file() and str(match) not in found:
                    found.append(str(match))
                    logger.debug("Found drift file: %s", match)
    return found


def match_drift_to_resource(
    entries: List[DriftEntry],
    resource_name: str,
    resource_group: str = "",
    resource_type: str = "",
) -> Optional[DriftEntry]:
    """
    Find a drift entry that matches a given Azure resource.

    Matching priority:
    1. Exact resource name + resource group match
    2. Exact resource name match only
    3. Case-insensitive resource name match

    Args:
        entries: List of DriftEntry objects.
        resource_name: Name of the Azure resource.
        resource_group: Resource group for extra matching.
        resource_type: Resource type for extra matching.

    Returns:
        Best matching DriftEntry, or None if no match found.
    """
    name_lower = resource_name.lower()
    rg_lower = resource_group.lower() if resource_group else ""

    # Priority 1: name + resource group exact match
    for entry in entries:
        if (
            entry.resource_name.lower() == name_lower
            and rg_lower
            and entry.resource_group.lower() == rg_lower
        ):
            return entry

    # Priority 2: name exact match
    for entry in entries:
        if entry.resource_name.lower() == name_lower:
            return entry

    # Priority 3: partial name match
    for entry in entries:
        entry_lower = entry.resource_name.lower()
        if name_lower in entry_lower or entry_lower in name_lower:
            return entry

    return None
