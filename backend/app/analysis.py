"""
backend/app/analysis.py — Shared static-analysis + agent-pipeline + persistence flow.

Extracted out of routers/cases.py so the same "analyze a file, run the agent
graph, save the result" flow can be triggered from two different entry
points: the interactive POST /api/cases/upload endpoint, and the background
ingestion_worker.py consumer that drains the ingestion gateway's Redis
queue. Keeping this in one place means both paths get identical behavior
(same normalization, same DB/ES writes) instead of two copies that could
drift apart.
"""

from __future__ import annotations

import logging
from pathlib import Path

from static_analysis.bootstrap import create_engine
from agents.orchestrator.schema import StaticAnalysisOutput, YaraMatch, ExtractedStrings
from agents.orchestrator.orchestrator import build_graph

from .models.api_models import risk_score_to_status
from . import geoip, store

_LOGGER = logging.getLogger(__name__)

_graph = build_graph()  # compiled once at import time, reused across all callers
_static_engine = create_engine()

_SUPPORTED_FILE_TYPES = ("apk", "pe", "exe", "dll", "elf", "mach_o")


class UnsupportedFormatError(ValueError):
    """Raised when the analyzed file isn't a format the engine supports."""


async def analyze_and_save(file_path: str | Path, event_type: str = "static_analysis_complete") -> dict:
    """
    Runs the full pipeline against a file already on disk: static analysis
    engine -> LangGraph agent orchestrator -> persisted case. Returns the
    case_data dict (the shape CaseDetail expects). Raises
    UnsupportedFormatError for a format the engine can't handle; any other
    failure propagates so the caller (HTTP route or queue consumer) decides
    how to report it.
    """
    raw_static = _static_engine.analyze(file_path)

    normalized_file_type = str(raw_static.get("file_type", "unknown")).lower()
    if normalized_file_type not in _SUPPORTED_FILE_TYPES:
        raise UnsupportedFormatError(
            f"Unsupported file format '{normalized_file_type}'. Supported: APK, PE/EXE/DLL, ELF, Mach-O."
        )

    platform = raw_static.get("platform")
    if platform not in ("android", "windows", "linux", "macos"):
        platform = (
            "android" if normalized_file_type == "apk"
            else "windows" if normalized_file_type in ("pe", "exe", "dll")
            else "linux" if normalized_file_type == "elf"
            else "macos"
        )

    yara_matches = [
        YaraMatch(
            rule_name=m["rule_name"],
            category=m["category"],
            severity="medium" if m["severity"] not in ("low", "medium", "high", "critical") else m["severity"],
            description=m["description"],
        )
        for m in raw_static.get("yara_matches", [])
    ]
    extracted_strings = ExtractedStrings(
        urls=raw_static.get("extracted_strings", {}).get("urls", []),
        ips=raw_static.get("extracted_strings", {}).get("ips", []),
        suspicious_keywords=raw_static.get("extracted_strings", {}).get("suspicious_keywords", []),
    )

    static_output = StaticAnalysisOutput(
        sample_id=raw_static["sha256"],  # real SHA-256 as the canonical case ID, not the engine's internal reference tag
        sha256=raw_static["sha256"],
        platform=platform,
        file_type=normalized_file_type,
        file_size_bytes=raw_static["file_size_bytes"],
        submitted_at=raw_static["submitted_at"],
        yara_matches=yara_matches,
        extracted_strings=extracted_strings,
    )

    initial_state = {"static_output": static_output, "dynamic_output": None}
    final_state = _graph.invoke(initial_state)

    case_data = {
        "sample_id": final_state["sample_id"],
        "platform": static_output.platform,
        "file_type": static_output.file_type,
        "file_size_bytes": static_output.file_size_bytes,
        "risk_score": final_state["risk_score"],
        "status": risk_score_to_status(final_state["risk_score"]),
        "mitre_techniques": [t.model_dump() for t in final_state["mitre_techniques"]],
        "capability_tags": [c.model_dump() for c in final_state["capability_tags"]],
        "narrative_summary": final_state["narrative_summary"],
        "submitted_at": static_output.submitted_at,
        # Real hashes and the richer static-analysis findings (YARA matches,
        # packing/unpacking result, explained-string IOCs) — the engine
        # already computes all of this; previously it was silently discarded
        # here instead of being handed to the frontend and PDF report.
        "sha256": raw_static.get("sha256"),
        "md5": raw_static.get("md5"),
        "sha1": raw_static.get("sha1"),
        "yara_matches": raw_static.get("yara_matches", []),
        "packing": raw_static.get("packing"),
        "explained_strings": raw_static.get("explained_strings", []),
        # Best-effort — geoip.lookup_many() returns [] whenever GEOIP_DB_PATH
        # isn't configured, never raising or blocking analysis.
        "geo_iocs": geoip.lookup_many(raw_static.get("extracted_strings", {}).get("ips", [])),
    }

    await store.save_case(case_data["sample_id"], case_data, event_type=event_type)
    return case_data
