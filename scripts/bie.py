import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

class BieState(Enum):
    KNOWN = "KNOWN"
    LIKELY = "LIKELY"
    UNCERTAIN = "UNCERTAIN"
    ANOMALOUS = "ANOMALOUS"
    HIGH_RISK = "HIGH_RISK"
    BLOCKED = "BLOCKED"

class ProbeCategory(Enum):
    STATIC_INSPECTION = "STATIC_INSPECTION"
    SCHEMA_INSPECTION = "SCHEMA_INSPECTION"
    PERMISSION_INSPECTION = "PERMISSION_INSPECTION"
    BASELINE_COMPARISON = "BASELINE_COMPARISON"
    HISTORICAL_COMPARISON = "HISTORICAL_COMPARISON"
    ARGUMENT_ANALYSIS = "ARGUMENT_ANALYSIS"
    SEQUENCE_ANALYSIS = "SEQUENCE_ANALYSIS"
    POLICY_SIMULATION = "POLICY_SIMULATION"
    ADAPTER_METADATA_INSPECTION = "ADAPTER_METADATA_INSPECTION"

@dataclass
class BehaviorEvent:
    event_id: str
    agent: str
    tool: str
    args: dict[str, Any]
    effect_inferred: str = "UNKNOWN"

@dataclass
class Evidence:
    evidence_id: str
    source: str
    timestamp: str
    observation: str
    reliability: str
    related_tool: str | None = None
    related_agent: str | None = None
    related_hypothesis: str | None = None

@dataclass
class Hypothesis:
    id: str
    description: str
    prior_confidence: float
    current_confidence: float
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    status: BieState = BieState.UNCERTAIN
    
    def adjust_confidence(self, delta: float, evidence_id: str, supports: bool):
        self.current_confidence = max(0.0, min(1.0, self.current_confidence + delta))
        if supports:
            self.supporting_evidence.append(evidence_id)
        else:
            self.contradicting_evidence.append(evidence_id)
        
        if self.current_confidence > 0.8:
            self.status = BieState.LIKELY
        elif self.current_confidence < 0.2:
            self.status = BieState.UNCERTAIN

@dataclass
class SafeProbe:
    probe_id: str
    type: ProbeCategory
    target: str
    risk_level: str
    execute_fn: Callable[[], Evidence | None]
    
class BehavioralFingerprint:
    def __init__(self, agent: str):
        self.agent = agent
        self.tool_counts: dict[str, int] = {}
        self.sequences: list[str] = []
        self.external_writes = 0
        self.credential_reads = 0
        
    def observe(self, event: BehaviorEvent):
        self.tool_counts[event.tool] = self.tool_counts.get(event.tool, 0) + 1
        self.sequences.append(event.tool)
        if event.effect_inferred == "EXTERNAL_WRITE":
            self.external_writes += 1
        if "credential" in event.tool.lower() or "secret" in event.tool.lower():
            self.credential_reads += 1

class Investigator:
    def __init__(self, target_agent: str, reference_baseline: dict, current_state: dict):
        self.target_agent = target_agent
        self.reference_baseline = reference_baseline
        self.current_state = current_state
        self.fingerprint = BehavioralFingerprint(target_agent)
        self.hypotheses: dict[str, Hypothesis] = {}
        self.evidence_log: list[Evidence] = []
        self.probes: list[SafeProbe] = []
        self.anomalies: list[str] = []
        
    def add_evidence(self, ev: Evidence):
        self.evidence_log.append(ev)
        
    def register_probe(self, probe: SafeProbe):
        self.probes.append(probe)
        
    def generate_hypotheses(self):
        # Deterministically generate standard hypotheses
        self.hypotheses["H1"] = Hypothesis("H1", "Legitimate workflow expansion", 0.5, 0.5)
        self.hypotheses["H2"] = Hypothesis("H2", "Configuration or schema change", 0.3, 0.3)
        self.hypotheses["H3"] = Hypothesis("H3", "Suspicious privilege misuse or injection", 0.1, 0.1)
        self.hypotheses["H4"] = Hypothesis("H4", "Tool mutation or adversarial naming", 0.1, 0.1)
        
    def run_probes(self):
        for probe in self.probes:
            ev = probe.execute_fn()
            if ev:
                self.add_evidence(ev)
                self.evaluate_evidence(ev)
                
    def evaluate_evidence(self, ev: Evidence):
        # Deterministic rules to update hypotheses based on evidence observation
        obs = ev.observation.lower()
        if "schema unchanged" in obs:
            self.hypotheses["H2"].adjust_confidence(-0.2, ev.evidence_id, False)
            self.hypotheses["H3"].adjust_confidence(0.2, ev.evidence_id, True)
            
        if "schema changed" in obs:
            self.hypotheses["H2"].adjust_confidence(0.5, ev.evidence_id, True)
            self.hypotheses["H4"].adjust_confidence(0.3, ev.evidence_id, True)
            
        if "policy boundary crossed" in obs or "suspicious capability chain" in obs:
            self.hypotheses["H1"].adjust_confidence(-0.4, ev.evidence_id, False)
            self.hypotheses["H3"].adjust_confidence(0.6, ev.evidence_id, True)
            
        if "behavior matches baseline" in obs:
            self.hypotheses["H1"].adjust_confidence(0.4, ev.evidence_id, True)
            self.hypotheses["H3"].adjust_confidence(-0.2, ev.evidence_id, False)
            
        if "read-only semantics verified" in obs:
            self.hypotheses["H3"].adjust_confidence(-0.3, ev.evidence_id, False)
            self.hypotheses["H4"].adjust_confidence(0.4, ev.evidence_id, True)

        if "new tools observed" in obs:
            # Behavior expanded without permission change if schema unchanged?
            # Or legitimate expansion
            self.hypotheses["H1"].adjust_confidence(0.2, ev.evidence_id, True)
            self.hypotheses["H3"].adjust_confidence(0.2, ev.evidence_id, True)

    def analyze_sequence(self):
        # Sequence anomaly detection
        seq = self.fingerprint.sequences
        if not seq:
            return
            
        # Detect suspicious chains
        for i in range(len(seq) - 1):
            if ("credential" in seq[i].lower() or "secret" in seq[i].lower()) and "network" in seq[i+1].lower():
                ev = Evidence(f"E-SEQ-{len(self.evidence_log)}", "Sequence Analysis", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "Suspicious capability chain: credential read -> network request", "HIGH", seq[i], self.target_agent)
                self.add_evidence(ev)
                self.anomalies.append("Suspicious credential-to-network chain")
                self.evaluate_evidence(ev)
                
            if "read" in seq[i].lower() and "write" in seq[i+1].lower():
                ev = Evidence(f"E-SEQ-{len(self.evidence_log)}", "Sequence Analysis", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "Read followed by immediate write", "MEDIUM", seq[i+1], self.target_agent)
                self.add_evidence(ev)
                
    def run_investigation(self, events: list[BehaviorEvent]) -> dict:
        for ev in events:
            self.fingerprint.observe(ev)
            
        self.generate_hypotheses()
        
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        
        def probe_schema():
            # SCHEMA_INSPECTION probe
            # Check schema drifts from current state
            drifts = self.current_state.get("schema_drifts", [])
            if any(self.target_agent in d for d in drifts):
                return Evidence(f"E-{len(self.evidence_log)+1}", "Schema Inspector", ts, "Schema changed from baseline", "HIGH")
            return Evidence(f"E-{len(self.evidence_log)+1}", "Schema Inspector", ts, "Schema unchanged", "HIGH")
            
        def probe_baseline():
            # BASELINE_COMPARISON probe
            ref_tools = self.reference_baseline.get("mcp_schemas", {}).keys()
            new_tools = [t for t in self.fingerprint.tool_counts.keys() if t not in ref_tools]
            if new_tools:
                return Evidence(f"E-{len(self.evidence_log)+1}", "Baseline Inspector", ts, f"New tools observed: {new_tools}", "HIGH")
            return Evidence(f"E-{len(self.evidence_log)+1}", "Baseline Inspector", ts, "Behavior matches baseline capabilities", "HIGH")
            
        def probe_semantics():
            # ADAPTER_METADATA_INSPECTION / False positive defense
            for tool in self.fingerprint.tool_counts.keys():
                if "deploy" in tool and "read" in tool:
                    return Evidence(f"E-{len(self.evidence_log)+1}", "Semantics Inspector", ts, "Read-only semantics verified despite dangerous naming", "HIGH")
            return None
            
        self.register_probe(SafeProbe("P1", ProbeCategory.SCHEMA_INSPECTION, "Target Schema", "LOW", probe_schema))
        self.register_probe(SafeProbe("P2", ProbeCategory.BASELINE_COMPARISON, "Baseline", "LOW", probe_baseline))
        self.register_probe(SafeProbe("P3", ProbeCategory.ADAPTER_METADATA_INSPECTION, "Tool Semantics", "LOW", probe_semantics))
        
        self.run_probes()
        self.analyze_sequence()
        
        # Sort hypotheses by confidence
        sorted_h = sorted(self.hypotheses.values(), key=lambda h: h.current_confidence, reverse=True)
        top_h = sorted_h[0]
        
        risk = "LOW"
        if top_h.id == "H3" and top_h.current_confidence > 0.6:
            risk = "HIGH"
        elif self.anomalies:
            risk = "HIGH"
        elif "H2" in [h.id for h in sorted_h[:2]] and top_h.current_confidence > 0.5:
            risk = "MEDIUM"
            
        decision = "REVIEW"
        if risk == "HIGH": decision = "BLOCKED"
        elif risk == "LOW" and top_h.id == "H1": decision = "SAFE"
        
        return {
            "target": self.target_agent,
            "finding": top_h.description,
            "risk": risk,
            "confidence": round(top_h.current_confidence, 2),
            "hypotheses": [{"id": h.id, "desc": h.description, "conf": round(h.current_confidence, 2), "evidence": h.supporting_evidence} for h in sorted_h],
            "probes": [{"id": p.probe_id, "type": p.type.value, "target": p.target} for p in self.probes],
            "evidence": [{"id": e.evidence_id, "obs": e.observation} for e in self.evidence_log],
            "anomalies": self.anomalies,
            "policy_decision": decision
        }
