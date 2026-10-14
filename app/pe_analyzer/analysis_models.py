"""Data models and options for core and extended PE analysis."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AnalysisOptions:
    authenticode: bool = False
    dotnet: bool = False
    die: str | None = None
    capa: str | None = None
    capa_rules: str | None = None
    capa_signatures: str | None = None
    floss: str | None = None
    tool_timeout: int = 60
    entropy_window: int = 4096

    def validate(self) -> None:
        if (self.capa_rules or self.capa_signatures) and not self.capa:
            raise ValueError("capa_rules and capa_signatures require a capa engine")
        for name, lower, upper in (
            ("tool_timeout", 1, 600),
            ("entropy_window", 512, 65536),
        ):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not lower <= value <= upper
            ):
                raise ValueError(
                    f"{name} must be an integer between {lower} and {upper}"
                )


@dataclass(slots=True)
class StageResult:
    status: str = "not_requested"
    version: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EntropyRegion:
    source: str
    file_offset: str
    size: int
    peak_entropy: float
    executable: bool = False


@dataclass(slots=True)
class EmbeddedPE:
    sha256: str
    size: int
    architecture: str
    section_count: int
    entry_point_rva: str
    imports: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ExtendedAnalysis:
    metadata: dict[str, Any] = field(default_factory=dict)
    structure: list[dict[str, str]] = field(default_factory=list)
    entropy_regions: list[EntropyRegion] = field(default_factory=list)
    embedded_pes: list[EmbeddedPE] = field(default_factory=list)
    regions: list[dict[str, Any]] = field(default_factory=list)
    stages: dict[str, StageResult] = field(default_factory=dict)


@dataclass(slots=True)
class FileMetadata:
    """Metadata and stable identifiers for the analyzed file."""

    filename: str
    file_size: int
    md5_hash: str
    sha1_hash: str
    sha256_hash: str
    is_packed: bool = False
    language_guess: str | None = None
    creation_time: str | None = None
    compilation_time: str | None = None
    architecture: str | None = None
    subsystem: str | None = None
    imphash: str | None = None


@dataclass(slots=True)
class SectionEntropy:
    """PE section properties used by structural and packing checks."""

    name: str
    virtual_address: str
    virtual_size: int
    raw_size: int
    entropy: float
    is_packed_suspicious: bool
    characteristics: int = 0
    is_readable: bool = False
    is_writable: bool = False
    is_executable: bool = False
    suspicious_reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FlaggedAPI:
    """An imported API associated with a potentially sensitive capability."""

    dll: str
    function_name: str
    category: str


@dataclass(slots=True)
class StaticFinding:
    rule_id: str
    title: str
    category: str
    severity: str
    score: int
    confidence: float
    evidence: list[str] = field(default_factory=list)
    description: str = ""


@dataclass(slots=True)
class StringIndicator:
    value: str
    category: str
    offset: str | None = None
    encoding: str = "ascii"
    source: str = "file"
    decoded_offset: str | None = None


@dataclass(slots=True)
class DecodedContent:
    """Candidate transformation with an offset relative to its immediate parent."""

    encoding: str
    size: int
    sha256: str
    detected_type: str
    suspected_role: str
    source_offset: str = "0x0"
    source_offset_unit: str = "characters"
    text: str | None = None
    text_truncated: bool = False
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ExtractedString:
    value: str
    offset: str | None
    encoding: str
    truncated: bool = False
    decoded: list[DecodedContent] = field(default_factory=list)
    suspected_hashes: list["SuspectedHash"] = field(default_factory=list)


@dataclass(slots=True)
class SuspectedHash:
    """A hash-shaped string; catalog matches are candidates, not proof."""

    value: str
    possible_algorithms: list[str]
    api_matches: list["ApiHashMatch"] = field(default_factory=list)
    source: str = "raw string"


@dataclass(frozen=True, slots=True)
class NameHash:
    algorithm: str
    value: str
    hashed_name: str
    encoding: str


@dataclass(frozen=True, slots=True)
class ApiHashMatch:
    api_name: str
    category: str
    algorithm: str
    hashed_name: str
    encoding: str


@dataclass(slots=True)
class ApiHashOccurrence:
    """Potential API-name hash stored directly as bytes in the file."""

    offset: str
    value: str
    byte_order: str
    api_name: str
    category: str
    algorithm: str
    hashed_name: str
    encoding: str


@dataclass(slots=True)
class ResourceInfo:
    resource_type: str
    name: str
    language: str
    size: int
    entropy: float
    file_signatures: list[str] = field(default_factory=list)
    suspected_name: str = "unknown resource"
    suspected_role: str = "unknown data"
    detected_type: str = "unknown"
    rva: str | None = None
    file_offset: str | None = None
    anomalies: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    decoded: list[DecodedContent] = field(default_factory=list)
    inspection_notes: list[str] = field(default_factory=list)
    origin: str = "resource directory"


@dataclass(slots=True)
class FileRegion:
    """A contiguous range of bytes in the analyzed file."""

    offset: str
    size: int


@dataclass(slots=True)
class OverlayInfo:
    present: bool = False
    offset: str | None = None
    size: int = 0
    entropy: float = 0.0
    file_signatures: list[str] = field(default_factory=list)
    regions: list[FileRegion] = field(default_factory=list)


@dataclass(slots=True)
class SignatureInfo:
    present: bool = False
    file_offset: str | None = None
    end_offset: str | None = None
    size: int = 0
    verification_status: str = "not_checked"
    certificate_count: int = 0
    table_valid: bool | None = None


@dataclass
class YaraScanResult:
    """Completed optional scan; an empty match list means no rules matched."""

    rules_file: str
    matched_rules: list[str] = field(default_factory=list)


@dataclass
class BinaryAnalysisResult:
    """Complete in-memory result from non-disassembly PE analysis."""

    file_metadata: FileMetadata
    sections: list[SectionEntropy]
    total_dlls: int
    total_imports: int
    all_imports: dict[str, dict[str, Any]]
    flagged_apis: list[FlaggedAPI] = field(default_factory=list)
    findings: list[StaticFinding] = field(default_factory=list)
    string_indicators: list[StringIndicator] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    resources: list[ResourceInfo] = field(default_factory=list)
    overlay: OverlayInfo = field(default_factory=OverlayInfo)
    signature: SignatureInfo = field(default_factory=SignatureInfo)
    entry_point_rva: str | None = None
    entry_point_section: str | None = None
    tls_callbacks: list[str] = field(default_factory=list)
    packer_indicators: list[str] = field(default_factory=list)
    security_features: dict[str, bool] = field(default_factory=dict)
    debug_paths: list[str] = field(default_factory=list)
    strings: list[ExtractedString] = field(default_factory=list)
    minimum_string_length: int | None = None
    analysis_notes: list[str] = field(default_factory=list)
    yara_scan: YaraScanResult | None = None
    api_hash_matches: list[ApiHashOccurrence] = field(default_factory=list)
    extended: ExtendedAnalysis = field(default_factory=ExtendedAnalysis)

    @property
    def has_packed_sections(self) -> bool:
        return any(sec.is_packed_suspicious for sec in self.sections)

    @property
    def risk_score(self) -> int:
        if self.findings:
            return min(100, sum(finding.score for finding in self.findings))
        score = len(self.flagged_apis)
        if self.has_packed_sections:
            score += 5
        return score

    @property
    def risk_level(self) -> str:
        score = self.risk_score
        if score >= 60:
            return "high"
        if score >= 25:
            return "medium"
        if score >= 10:
            return "low"
        return "informational"
