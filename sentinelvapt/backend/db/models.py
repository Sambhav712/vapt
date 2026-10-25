"""
SentinelVAPT — SQLAlchemy ORM Models
All job state, findings, defensive rules, and raw tool outputs are persisted here.
"""

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Text, DateTime, Enum, Float, Boolean, ForeignKey, JSON, Integer, Uuid
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class ScopeType(str, enum.Enum):
    WEB = "web"
    API = "api"
    NETWORK = "network"


class PipelineStage(str, enum.Enum):
    TOOL_CHECK = "tool_check"
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    EXPLOITATION = "exploitation"
    AI_ANALYSIS = "ai_analysis"
    REPORT_GENERATION = "report_generation"
    DEFENSIVE_RULE_GENERATION = "defensive_rule_generation"
    DONE = "done"
    FAILED = "failed"


class StageStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


def _utcnow():
    return datetime.now(timezone.utc)


class Job(Base):
    """Represents a single scan job / pipeline run."""
    __tablename__ = "jobs"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target = Column(String(512), nullable=False)
    scope_type = Column(Enum(ScopeType), nullable=False)
    authorized_exploitation = Column(Boolean, default=False)
    current_stage = Column(Enum(PipelineStage), default=PipelineStage.TOOL_CHECK)
    stage_statuses = Column(JSON, default=dict)
    # JSON dict: {"recon": "completed", "vuln_scan": "running", ...}
    enabled_tools = Column(JSON, default=list)
    disabled_tools = Column(JSON, default=list)

    executive_summary = Column(Text, nullable=True)
    ai_analysis_result = Column(JSON, nullable=True)

    report_pdf_path = Column(String(1024), nullable=True)
    report_json_path = Column(String(1024), nullable=True)
    report_md_path = Column(String(1024), nullable=True)

    logs = Column(JSON, default=list)  # list of {"ts": ..., "stage": ..., "msg": ...}

    created_at = Column(DateTime(timezone=True), default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="job", cascade="all, delete-orphan")
    tool_outputs = relationship("ToolOutput", back_populates="job", cascade="all, delete-orphan")
    defensive_rules = relationship("DefensiveRule", back_populates="job", cascade="all, delete-orphan")

    def add_log(self, stage: str, message: str):
        if self.logs is None:
            self.logs = []
        self.logs = self.logs + [{
            "ts": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "msg": message,
        }]


class ToolOutput(Base):
    """Raw output from a single tool invocation."""
    __tablename__ = "tool_outputs"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(Uuid(as_uuid=True), ForeignKey("jobs.id"), nullable=False)
    tool_name = Column(String(64), nullable=False)  # nmap, nuclei, zap, etc.
    stage = Column(Enum(PipelineStage), nullable=False)
    command = Column(Text, nullable=True)
    stdout = Column(Text, nullable=True)
    stderr = Column(Text, nullable=True)
    parsed_output = Column(JSON, nullable=True)
    exit_code = Column(Integer, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    job = relationship("Job", back_populates="tool_outputs")


class Finding(Base):
    """A normalized vulnerability finding, possibly AI-enhanced."""
    __tablename__ = "findings"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(Uuid(as_uuid=True), ForeignKey("jobs.id"), nullable=False)

    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(Severity), default=Severity.INFO)
    confidence = Column(Enum(Confidence), default=Confidence.MEDIUM)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(256), nullable=True)
    cve_ids = Column(JSON, default=list)  # list of CVE strings
    cwe_ids = Column(JSON, default=list)  # list of CWE strings

    affected_asset = Column(String(512), nullable=True)
    affected_component = Column(String(512), nullable=True)
    evidence = Column(Text, nullable=True)  # PoC / proof
    remediation = Column(Text, nullable=True)

    source_tool = Column(String(64), nullable=True)
    is_false_positive = Column(Boolean, default=False)
    ai_reasoning = Column(Text, nullable=True)
    attack_chain = Column(Text, nullable=True)

    mitre_tactic = Column(String(128), nullable=True)
    mitre_technique_id = Column(String(32), nullable=True)
    mitre_technique_name = Column(String(256), nullable=True)

    raw_data = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    job = relationship("Job", back_populates="findings")
    defensive_rules = relationship("DefensiveRule", back_populates="finding", cascade="all, delete-orphan")


class DefensiveRule(Base):
    """Auto-generated defensive rules for a finding."""
    __tablename__ = "defensive_rules"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(Uuid(as_uuid=True), ForeignKey("jobs.id"), nullable=False)
    finding_id = Column(Uuid(as_uuid=True), ForeignKey("findings.id"), nullable=False)

    sigma_rule = Column(Text, nullable=True)
    sigma_valid = Column(Boolean, nullable=True)
    wazuh_rule = Column(Text, nullable=True)
    suricata_rule = Column(Text, nullable=True)
    firewall_rule = Column(Text, nullable=True)

    mitre_tactic = Column(String(128), nullable=True)
    mitre_technique_id = Column(String(32), nullable=True)
    mitre_technique_name = Column(String(256), nullable=True)

    created_at = Column(DateTime(timezone=True), default=_utcnow)

    job = relationship("Job", back_populates="defensive_rules")
    finding = relationship("Finding", back_populates="defensive_rules")
