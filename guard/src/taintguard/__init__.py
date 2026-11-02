"""Lineage-based taint tracking and agent-boundary guard."""

from taintguard.contracts import ContractError, ContractSet, Trust, load_contracts
from taintguard.extractor import (
    ExtractionResult,
    QuarantinedExtractor,
    SchemaNotClosed,
    check_schema_closed,
    render_extraction,
    shape,
    shape_record,
)
from taintguard.lineage import (
    Catalog,
    ColumnTaint,
    LineageError,
    QueryTaint,
    analyze_query,
    build_catalog,
)
from taintguard.policy import (
    ArgRule,
    Capabilities,
    Decision,
    ToolPolicy,
    ToolVerdict,
    check_call,
    contacts,
    max_ngram_overlap,
)
from taintguard.provenance import ProvenanceVerdict, TieredResult, check_answer, extract_claims

__version__ = "0.1.0"

__all__ = [
    "ArgRule", "Capabilities", "Catalog", "ColumnTaint", "ContractError", "ContractSet", "Decision",
    "ExtractionResult", "LineageError", "ProvenanceVerdict", "QuarantinedExtractor", "QueryTaint",
    "SchemaNotClosed", "TieredResult", "ToolPolicy", "ToolVerdict", "Trust", "analyze_query",
    "build_catalog", "check_answer", "check_call", "check_schema_closed", "contacts",
    "extract_claims", "load_contracts", "max_ngram_overlap", "render_extraction", "shape", "shape_record",
]  # fmt: skip
