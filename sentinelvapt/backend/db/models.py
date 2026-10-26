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
    AI_ORCHESTRATION = "ai_orchestration"
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

    # AI Orchestration fields
    ai_orchestration_mode = Column(String(32), default="ai_driven")  # "ai_driven" or "heuristic_fallback"
    current_iteration = Column(Integer, default=0)
    max_iterations = Column(Integer, default=20)

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
    ai_decisions = relationship("AIDecisionLog", back_populates="job", cascade="all, delete-orphan", order_by="AIDecisionLog.iteration")
    agent_sessions = relationship("AgentSession", back_populates="job", cascade="all, delete-orphan")

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


class AIDecisionLog(Base):
    """Log of every AI decision in the dynamic orchestration loop."""
    __tablename__ = "ai_decision_logs"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(Uuid(as_uuid=True), ForeignKey("jobs.id"), nullable=False)
    iteration = Column(Integer, nullable=False)
    chosen_tool = Column(String(64), nullable=True)
    action = Column(String(32), nullable=False)  # run_tool, finish, need_authorization, fallback
    reasoning = Column(Text, nullable=True)
    expected_outcome = Column(Text, nullable=True)
    confidence = Column(Float, nullable=True)
    tool_args = Column(JSON, default=dict)
    tool_execution_result = Column(JSON, default=dict)
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    latency = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    job = relationship("Job", back_populates="ai_decisions")


class AgentSession(Base):
    """Persistent record of an autonomous agent session."""
    __tablename__ = "agent_sessions"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(Uuid(as_uuid=True), ForeignKey("jobs.id"), nullable=False)
    session_id = Column(String(64), unique=True, nullable=False)
    target = Column(String(512), nullable=False)
    scope_type = Column(String(32), nullable=False)
    authorized_exploitation = Column(Boolean, default=False)
    goal = Column(Text, nullable=True)

    status = Column(String(32), default="running")  # running, completed, failed, cancelled
    final_summary = Column(Text, nullable=True)

    step_count = Column(Integer, default=0)
    finding_count = Column(Integer, default=0)
    total_commands_executed = Column(Integer, default=0)
    total_commands_blocked = Column(Integer, default=0)
    total_llm_calls = Column(Integer, default=0)
    total_llm_latency = Column(Float, default=0.0)
    installed_tools = Column(JSON, default=list)
    findings_data = Column(JSON, default=list)

    started_at = Column(DateTime(timezone=True), default=_utcnow)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    job = relationship("Job", back_populates="agent_sessions")
    steps = relationship("AgentStepLog", back_populates="session", cascade="all, delete-orphan",
                         order_by="AgentStepLog.step_number")


class AgentStepLog(Base):
    """Persistent log of each step in an agent session."""
    __tablename__ = "agent_step_logs"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(Uuid(as_uuid=True), ForeignKey("agent_sessions.id"), nullable=False)
    step_number = Column(Integer, nullable=False)

    thought = Column(Text, nullable=True)
    action = Column(String(32), nullable=False)
    command = Column(Text, nullable=True)
    tool_name = Column(String(64), nullable=True)
    confidence = Column(Float, default=0.0)

    result_exit_code = Column(Integer, nullable=True)
    result_stdout = Column(Text, nullable=True)
    result_stderr = Column(Text, nullable=True)
    result_success = Column(Boolean, default=False)
    result_blocked = Column(Boolean, default=False)
    result_block_reason = Column(Text, nullable=True)
    result_duration = Column(Float, default=0.0)
    result_message = Column(Text, nullable=True)

    finding_data = Column(JSON, nullable=True)

    llm_latency = Column(Float, default=0.0)
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)

    created_at = Column(DateTime(timezone=True), default=_utcnow)

    session = relationship("AgentSession", back_populates="steps")
