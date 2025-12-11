#!/usr/bin/env python3
"""
HydraRecon Risk Scoring & Prioritization Module
Enterprise risk assessment and vulnerability prioritization engine.
"""

import asyncio
import hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import logging
import json


class RiskCategory(Enum):
    """Risk categories"""
    VULNERABILITY = "vulnerability"
    CONFIGURATION = "configuration"
    EXPOSURE = "exposure"
    COMPLIANCE = "compliance"
    BUSINESS = "business"
    THREAT = "threat"


class RiskLevel(Enum):
    """Risk severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AssetCriticality(Enum):
    """Asset criticality levels"""
    CROWN_JEWEL = "crown_jewel"
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ExploitMaturity(Enum):
    """Exploit maturity levels"""
    WEAPONIZED = "weaponized"
    POC = "proof_of_concept"
    FUNCTIONAL = "functional"
    UNPROVEN = "unproven"
    NOT_DEFINED = "not_defined"


@dataclass
class Asset:
    """Represents an organizational asset"""
    id: str
    name: str
    type: str  # server, database, application, network, endpoint
    criticality: AssetCriticality
    owner: str
    department: str
    data_classification: str
    ip_addresses: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    compliance_requirements: List[str] = field(default_factory=list)
    business_value: float = 0.0  # 0-100
    exposure_score: float = 0.0  # 0-100
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskFactor:
    """Individual risk factor"""
    id: str
    name: str
    category: RiskCategory
    description: str
    base_score: float  # CVSS-like 0-10
    impact_score: float = 0.0
    exploitability_score: float = 0.0
    temporal_score: float = 0.0
    environmental_score: float = 0.0
    exploit_maturity: ExploitMaturity = ExploitMaturity.NOT_DEFINED
    threat_intel_indicators: int = 0
    affected_assets: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class RiskScore:
    """Calculated risk score for an asset or vulnerability"""
    id: str
    entity_id: str
    entity_type: str  # asset, vulnerability, exposure
    entity_name: str
    raw_score: float  # 0-100
    weighted_score: float  # 0-100
    risk_level: RiskLevel
    contributing_factors: List[Dict[str, Any]] = field(default_factory=list)
    prioritization_rank: int = 0
    sla_due: Optional[datetime] = None
    calculated_at: datetime = field(default_factory=datetime.now)


@dataclass
class RiskTrend:
    """Risk trend over time"""
    entity_id: str
    timestamp: datetime
    score: float
    delta: float
    risk_level: RiskLevel


@dataclass
class RemediationTask:
    """Remediation task for addressing risk"""
    id: str
    risk_score_id: str
    title: str
    description: str
    priority: int  # 1-5
    effort: str  # low, medium, high
    impact_reduction: float  # Expected score reduction
    status: str = "pending"  # pending, in_progress, completed, deferred
    assignee: Optional[str] = None
    due_date: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None


class RiskScoringEngine:
    """Enterprise Risk Scoring and Prioritization Engine"""
    
    def __init__(self):
        self.logger = logging.getLogger("RiskScoringEngine")
        self.assets: Dict[str, Asset] = {}
        self.risk_factors: Dict[str, RiskFactor] = {}
        self.risk_scores: Dict[str, RiskScore] = {}
        self.trends: List[RiskTrend] = []
        self.remediation_tasks: Dict[str, RemediationTask] = {}
        self._init_scoring_weights()
        self._init_sla_matrix()
    
    def _init_scoring_weights(self):
        """Initialize scoring weights"""
        self.weights = {
            "base_cvss": 0.30,
            "exploit_maturity": 0.20,
            "asset_criticality": 0.20,
            "threat_intel": 0.15,
            "exposure": 0.10,
            "compliance": 0.05
        }
        
        self.criticality_multipliers = {
            AssetCriticality.CROWN_JEWEL: 2.0,
            AssetCriticality.CRITICAL: 1.5,
            AssetCriticality.HIGH: 1.2,
            AssetCriticality.MEDIUM: 1.0,
            AssetCriticality.LOW: 0.8
        }
        
        self.exploit_maturity_scores = {
            ExploitMaturity.WEAPONIZED: 100,
            ExploitMaturity.FUNCTIONAL: 80,
            ExploitMaturity.POC: 60,
            ExploitMaturity.UNPROVEN: 40,
            ExploitMaturity.NOT_DEFINED: 20
        }
    
    def _init_sla_matrix(self):
        """Initialize SLA matrix for remediation"""
        self.sla_matrix = {
            RiskLevel.CRITICAL: timedelta(hours=24),
            RiskLevel.HIGH: timedelta(days=7),
            RiskLevel.MEDIUM: timedelta(days=30),
            RiskLevel.LOW: timedelta(days=90),
            RiskLevel.INFO: timedelta(days=180)
        }
    
    async def add_asset(
        self,
        name: str,
        asset_type: str,
        criticality: AssetCriticality,
        owner: str,
        department: str,
        data_classification: str,
        ip_addresses: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
        business_value: float = 50.0
    ) -> Asset:
        """Add an asset to the inventory"""
        asset_id = hashlib.sha256(
            f"{name}{asset_type}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        asset = Asset(
            id=asset_id,
            name=name,
            type=asset_type,
            criticality=criticality,
            owner=owner,
            department=department,
            data_classification=data_classification,
            ip_addresses=ip_addresses or [],
            services=services or [],
            business_value=business_value
        )
        
        self.assets[asset_id] = asset
        return asset
    
    async def add_risk_factor(
        self,
        name: str,
        category: RiskCategory,
        description: str,
        base_score: float,
        affected_asset_ids: List[str],
        exploit_maturity: ExploitMaturity = ExploitMaturity.NOT_DEFINED,
        cve_ids: Optional[List[str]] = None,
        threat_intel_indicators: int = 0
    ) -> RiskFactor:
        """Add a risk factor"""
        risk_id = hashlib.sha256(
            f"{name}{category.value}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Calculate sub-scores
        impact = min(base_score * 1.2, 10.0) if base_score >= 7.0 else base_score * 0.8
        exploitability = self.exploit_maturity_scores.get(exploit_maturity, 20) / 10
        
        risk_factor = RiskFactor(
            id=risk_id,
            name=name,
            category=category,
            description=description,
            base_score=base_score,
            impact_score=impact,
            exploitability_score=exploitability,
            exploit_maturity=exploit_maturity,
            threat_intel_indicators=threat_intel_indicators,
            affected_assets=affected_asset_ids,
            cve_ids=cve_ids or []
        )
        
        self.risk_factors[risk_id] = risk_factor
        
        # Recalculate affected asset scores
        for asset_id in affected_asset_ids:
            if asset_id in self.assets:
                await self.calculate_asset_risk_score(asset_id)
        
        return risk_factor
    
    async def calculate_asset_risk_score(self, asset_id: str) -> RiskScore:
        """Calculate risk score for an asset"""
        if asset_id not in self.assets:
            raise ValueError(f"Unknown asset: {asset_id}")
        
        asset = self.assets[asset_id]
        
        # Find all risk factors affecting this asset
        affecting_factors = [
            rf for rf in self.risk_factors.values()
            if asset_id in rf.affected_assets
        ]
        
        if not affecting_factors:
            # No risks - return minimal score
            score_id = hashlib.sha256(
                f"{asset_id}{datetime.now().isoformat()}".encode()
            ).hexdigest()[:16]
            
            risk_score = RiskScore(
                id=score_id,
                entity_id=asset_id,
                entity_type="asset",
                entity_name=asset.name,
                raw_score=0,
                weighted_score=0,
                risk_level=RiskLevel.INFO
            )
            self.risk_scores[score_id] = risk_score
            return risk_score
        
        # Calculate base score from factors
        total_base = sum(rf.base_score for rf in affecting_factors) / len(affecting_factors)
        
        # Calculate exploit maturity component
        max_maturity = max(
            self.exploit_maturity_scores.get(rf.exploit_maturity, 0)
            for rf in affecting_factors
        )
        
        # Calculate threat intel component
        total_indicators = sum(rf.threat_intel_indicators for rf in affecting_factors)
        threat_intel_score = min(100, total_indicators * 10)
        
        # Calculate exposure component
        exposure_score = asset.exposure_score
        
        # Calculate compliance component
        compliance_score = 100 if asset.compliance_requirements else 50
        
        # Apply weights
        raw_score = (
            self.weights["base_cvss"] * (total_base * 10) +
            self.weights["exploit_maturity"] * max_maturity +
            self.weights["threat_intel"] * threat_intel_score +
            self.weights["exposure"] * exposure_score +
            self.weights["compliance"] * compliance_score
        )
        
        # Apply asset criticality multiplier
        criticality_mult = self.criticality_multipliers.get(asset.criticality, 1.0)
        weighted_score = min(100, raw_score * criticality_mult)
        
        # Determine risk level
        risk_level = self._score_to_level(weighted_score)
        
        # Create score record
        score_id = hashlib.sha256(
            f"{asset_id}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        risk_score = RiskScore(
            id=score_id,
            entity_id=asset_id,
            entity_type="asset",
            entity_name=asset.name,
            raw_score=raw_score,
            weighted_score=weighted_score,
            risk_level=risk_level,
            contributing_factors=[
                {
                    "factor_id": rf.id,
                    "name": rf.name,
                    "category": rf.category.value,
                    "score": rf.base_score
                }
                for rf in affecting_factors
            ],
            sla_due=datetime.now() + self.sla_matrix.get(risk_level, timedelta(days=90))
        )
        
        self.risk_scores[score_id] = risk_score
        
        # Record trend
        self._record_trend(asset_id, weighted_score, risk_level)
        
        return risk_score
    
    def _score_to_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level"""
        if score >= 90:
            return RiskLevel.CRITICAL
        elif score >= 70:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def _record_trend(self, entity_id: str, score: float, level: RiskLevel):
        """Record risk trend data point"""
        # Get previous score
        previous = [t for t in self.trends if t.entity_id == entity_id]
        delta = score - previous[-1].score if previous else 0
        
        trend = RiskTrend(
            entity_id=entity_id,
            timestamp=datetime.now(),
            score=score,
            delta=delta,
            risk_level=level
        )
        self.trends.append(trend)
    
    async def prioritize_risks(self) -> List[RiskScore]:
        """Prioritize all risk scores"""
        scores = list(self.risk_scores.values())
        
        # Sort by weighted score descending
        scores.sort(key=lambda s: s.weighted_score, reverse=True)
        
        # Assign prioritization ranks
        for rank, score in enumerate(scores, 1):
            score.prioritization_rank = rank
        
        return scores
    
    async def get_top_risks(self, limit: int = 10) -> List[RiskScore]:
        """Get top risks by priority"""
        prioritized = await self.prioritize_risks()
        return prioritized[:limit]
    
    async def create_remediation_task(
        self,
        risk_score_id: str,
        title: str,
        description: str,
        effort: str = "medium",
        assignee: Optional[str] = None
    ) -> RemediationTask:
        """Create remediation task for a risk"""
        if risk_score_id not in self.risk_scores:
            raise ValueError(f"Unknown risk score: {risk_score_id}")
        
        risk_score = self.risk_scores[risk_score_id]
        
        task_id = hashlib.sha256(
            f"{risk_score_id}{title}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Calculate priority based on risk level
        priority_map = {
            RiskLevel.CRITICAL: 1,
            RiskLevel.HIGH: 2,
            RiskLevel.MEDIUM: 3,
            RiskLevel.LOW: 4,
            RiskLevel.INFO: 5
        }
        
        task = RemediationTask(
            id=task_id,
            risk_score_id=risk_score_id,
            title=title,
            description=description,
            priority=priority_map.get(risk_score.risk_level, 3),
            effort=effort,
            impact_reduction=risk_score.weighted_score * 0.5,  # Estimated 50% reduction
            assignee=assignee,
            due_date=risk_score.sla_due
        )
        
        self.remediation_tasks[task_id] = task
        return task
    
    async def get_risk_summary(self) -> Dict[str, Any]:
        """Get overall risk summary"""
        scores = list(self.risk_scores.values())
        
        by_level = {level.value: 0 for level in RiskLevel}
        for score in scores:
            by_level[score.risk_level.value] += 1
        
        # Calculate average score
        avg_score = sum(s.weighted_score for s in scores) / len(scores) if scores else 0
        
        # Count overdue items
        now = datetime.now()
        overdue = sum(1 for s in scores if s.sla_due and s.sla_due < now)
        
        # Get trend (compare to 7 days ago)
        week_ago = now - timedelta(days=7)
        recent_trends = [t for t in self.trends if t.timestamp >= week_ago]
        avg_delta = sum(t.delta for t in recent_trends) / len(recent_trends) if recent_trends else 0
        
        return {
            "timestamp": now.isoformat(),
            "total_risks": len(scores),
            "by_level": by_level,
            "average_score": round(avg_score, 1),
            "overdue_items": overdue,
            "trend_direction": "increasing" if avg_delta > 0 else "decreasing" if avg_delta < 0 else "stable",
            "trend_delta": round(avg_delta, 1),
            "total_assets": len(self.assets),
            "remediation_tasks": {
                "total": len(self.remediation_tasks),
                "pending": sum(1 for t in self.remediation_tasks.values() if t.status == "pending"),
                "in_progress": sum(1 for t in self.remediation_tasks.values() if t.status == "in_progress"),
                "completed": sum(1 for t in self.remediation_tasks.values() if t.status == "completed")
            }
        }
    
    async def get_department_risk_breakdown(self) -> Dict[str, Dict[str, Any]]:
        """Get risk breakdown by department"""
        departments = {}
        
        for asset in self.assets.values():
            if asset.department not in departments:
                departments[asset.department] = {
                    "assets": 0,
                    "total_risk_score": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                }
            
            dept = departments[asset.department]
            dept["assets"] += 1
            
            # Find risk score for this asset
            asset_scores = [
                s for s in self.risk_scores.values()
                if s.entity_id == asset.id
            ]
            
            if asset_scores:
                latest = max(asset_scores, key=lambda s: s.calculated_at)
                dept["total_risk_score"] += latest.weighted_score
                dept[latest.risk_level.value] += 1
        
        # Calculate averages
        for dept_name, dept in departments.items():
            if dept["assets"] > 0:
                dept["average_risk"] = round(dept["total_risk_score"] / dept["assets"], 1)
        
        return departments
    
    async def simulate_remediation_impact(
        self,
        risk_factor_ids: List[str]
    ) -> Dict[str, Any]:
        """Simulate impact of remediating specific risk factors"""
        # Get current state
        current_summary = await self.get_risk_summary()
        
        # Calculate what scores would be without these factors
        projected_scores = {}
        for score in self.risk_scores.values():
            # Remove contribution from specified factors
            remaining_factors = [
                f for f in score.contributing_factors
                if f["factor_id"] not in risk_factor_ids
            ]
            
            if remaining_factors:
                new_raw = sum(f["score"] * 10 for f in remaining_factors) / len(remaining_factors)
            else:
                new_raw = 0
            
            # Apply weights (simplified)
            projected_scores[score.id] = new_raw * 0.3
        
        # Calculate projected summary
        avg_projected = sum(projected_scores.values()) / len(projected_scores) if projected_scores else 0
        
        return {
            "current_average_score": current_summary["average_score"],
            "projected_average_score": round(avg_projected, 1),
            "score_reduction": round(current_summary["average_score"] - avg_projected, 1),
            "percentage_improvement": round(
                ((current_summary["average_score"] - avg_projected) / current_summary["average_score"]) * 100
                if current_summary["average_score"] > 0 else 0, 1
            ),
            "factors_addressed": len(risk_factor_ids),
            "affected_assets": sum(
                len(self.risk_factors[fid].affected_assets)
                for fid in risk_factor_ids if fid in self.risk_factors
            )
        }
    
    async def generate_risk_report(self) -> Dict[str, Any]:
        """Generate comprehensive risk report"""
        summary = await self.get_risk_summary()
        top_risks = await self.get_top_risks(10)
        dept_breakdown = await self.get_department_risk_breakdown()
        
        # Get critical factors
        critical_factors = [
            {
                "id": rf.id,
                "name": rf.name,
                "category": rf.category.value,
                "base_score": rf.base_score,
                "exploit_maturity": rf.exploit_maturity.value,
                "affected_assets": len(rf.affected_assets),
                "cves": rf.cve_ids
            }
            for rf in self.risk_factors.values()
            if rf.base_score >= 7.0
        ]
        
        return {
            "generated_at": datetime.now().isoformat(),
            "summary": summary,
            "top_risks": [
                {
                    "rank": s.prioritization_rank,
                    "entity_name": s.entity_name,
                    "score": s.weighted_score,
                    "level": s.risk_level.value,
                    "sla_due": s.sla_due.isoformat() if s.sla_due else None
                }
                for s in top_risks
            ],
            "department_breakdown": dept_breakdown,
            "critical_risk_factors": critical_factors[:10],
            "recommendations": self._generate_recommendations(summary, critical_factors)
        }
    
    def _generate_recommendations(
        self,
        summary: Dict[str, Any],
        critical_factors: List[Dict]
    ) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if summary["by_level"]["critical"] > 0:
            recommendations.append(
                f"Address {summary['by_level']['critical']} critical risk(s) immediately within 24-hour SLA"
            )
        
        if summary["overdue_items"] > 0:
            recommendations.append(
                f"Prioritize {summary['overdue_items']} overdue remediation items"
            )
        
        if summary["trend_direction"] == "increasing":
            recommendations.append(
                "Risk trend is increasing - review recent changes and new vulnerabilities"
            )
        
        if critical_factors:
            high_exploit = [f for f in critical_factors if f["exploit_maturity"] == "weaponized"]
            if high_exploit:
                recommendations.append(
                    f"Prioritize patching for {len(high_exploit)} vulnerabilities with weaponized exploits"
                )
        
        return recommendations
