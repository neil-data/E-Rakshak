import shutil
import tempfile
import logging
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Query

from agents.orchestrator.orchestrator import build_graph
from ..analysis import analyze_and_save, UnsupportedFormatError
from ..models.api_models import (
    SubmitSampleRequest,
    CaseSummary,
    CaseDetail,
    risk_score_to_status,
)
from ..store import save_case, get_case, list_cases
from .. import search
from ..auth import get_current_user

router = APIRouter(prefix="/api/cases", tags=["cases"])

_LOGGER = logging.getLogger(__name__)

_graph = build_graph()  # compiled once at import time, reused by /submit (which doesn't touch the file system)


@router.post("/upload", response_model=CaseDetail)
async def upload_sample(file: UploadFile = File(...), current_user: str = Depends(get_current_user)):
    """
    Receives an uploaded binary file (APK, EXE, DLL, ELF, Mach-O), runs the 9-step
    StaticAnalysisEngine pipeline, triggers the LangGraph agent orchestrator,
    persists the result (Postgres + Elasticsearch when available), and returns
    a complete evidence-grade CaseDetail.
    """
    temp_dir = tempfile.mkdtemp(prefix="sentinel_upload_")
    file_path = Path(temp_dir) / file.filename
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        case_data = await analyze_and_save(file_path, event_type="static_analysis_complete")
        return CaseDetail(**case_data)

    except UnsupportedFormatError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except HTTPException:
        raise
    except (ValueError, FileNotFoundError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        _LOGGER.exception("Upload & analysis failed")
        raise HTTPException(status_code=500, detail=f"Upload & analysis failed: {type(e).__name__}: {e}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.post("/submit", response_model=CaseDetail)
async def submit_sample(request: SubmitSampleRequest, current_user: str = Depends(get_current_user)):
    """
    Runs the full agent pipeline against submitted static/dynamic analysis data
    (used when static/dynamic results are already computed elsewhere, rather
    than uploading a raw file).
    """
    initial_state = {
        "static_output": request.static_analysis,
        "dynamic_output": request.dynamic_analysis,
    }

    try:
        final_state = _graph.invoke(initial_state)

        case_data = {
            "sample_id": final_state["sample_id"],
            "platform": request.static_analysis.platform,
            "file_type": request.static_analysis.file_type,
            "file_size_bytes": request.static_analysis.file_size_bytes,
            "risk_score": final_state["risk_score"],
            "status": risk_score_to_status(final_state["risk_score"]),
            "mitre_techniques": [t.model_dump() for t in final_state["mitre_techniques"]],
            "capability_tags": [c.model_dump() for c in final_state["capability_tags"]],
            "narrative_summary": final_state["narrative_summary"],
            "submitted_at": request.static_analysis.submitted_at,
            # /submit takes pre-computed static analysis (no direct file access),
            # so only the sha256 + YARA matches already present on the submitted
            # payload are available — md5/sha1/packing/explained_strings require
            # running the actual engine, which only /upload does.
            "sha256": request.static_analysis.sha256,
            "yara_matches": [m.model_dump() for m in request.static_analysis.yara_matches],
        }
    except HTTPException:
        raise
    except Exception as e:
        # Broadened from a bare graph-invoke try/except: a malformed final_state
        # (missing key) previously threw an unguarded KeyError past this point
        # and surfaced as a raw 500 with no HTTPException detail.
        _LOGGER.exception("Analysis pipeline failed for /api/cases/submit")
        raise HTTPException(status_code=500, detail=f"Analysis pipeline failed: {type(e).__name__}: {e}")

    await save_case(case_data["sample_id"], case_data, event_type="static_analysis_complete")
    return CaseDetail(**case_data)


@router.get("/search", response_model=list[CaseSummary])
async def search_cases_endpoint(q: str = Query(..., min_length=1), current_user: str = Depends(get_current_user)):
    """
    Elasticsearch-backed case search. Falls back to substring-matching the
    full case list when Elasticsearch is unavailable, so search never just
    breaks — it only loses fuzzy/full-text matching until ES comes back.
    """
    matched_ids = await search.search_cases(q)
    all_cases = await list_cases()

    if matched_ids is not None:
        matched_set = set(matched_ids)
        results = [c for c in all_cases if c["sample_id"] in matched_set]
    else:
        needle = q.lower()
        results = [
            c for c in all_cases
            if needle in c["sample_id"].lower() or needle in (c.get("narrative_summary") or "").lower()
        ]

    return [
        CaseSummary(
            sample_id=c["sample_id"], platform=c["platform"], file_type=c["file_type"],
            risk_score=c["risk_score"], status=c["status"], submitted_at=c["submitted_at"],
        )
        for c in results
    ]


@router.get("", response_model=list[CaseSummary])
async def get_all_cases(current_user: str = Depends(get_current_user)):
    """Case table data for the dashboard's main list view."""
    cases = await list_cases()
    return [
        CaseSummary(
            sample_id=c["sample_id"], platform=c["platform"], file_type=c["file_type"],
            risk_score=c["risk_score"], status=c["status"], submitted_at=c["submitted_at"],
        )
        for c in cases
    ]


@router.get("/{sample_id}", response_model=CaseDetail)
async def get_case_detail(sample_id: str, current_user: str = Depends(get_current_user)):
    """Full case detail for the dashboard's case detail panel."""
    case_data = await get_case(sample_id)
    if case_data is None:
        raise HTTPException(status_code=404, detail=f"Case {sample_id} not found")
    return CaseDetail(**case_data)
