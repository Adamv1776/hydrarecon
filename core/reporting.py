#!/usr/bin/env python3
"""
HydraRecon Advanced Reporting Engine
████████████████████████████████████████████████████████████████████████████████
█  PROFESSIONAL SECURITY REPORTS - PDF/HTML Export with Executive Summaries    █
████████████████████████████████████████████████████████████████████████████████
"""

import os
import json
import base64
from datetime import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
import html
import hashlib


class ReportFormat(Enum):
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"
    MARKDOWN = "markdown"
    XML = "xml"


class SeverityLevel(Enum):
    CRITICAL = ("Critical", "#ff0040", 10)
    HIGH = ("High", "#ff4444", 8)
    MEDIUM = ("Medium", "#ffaa00", 5)
    LOW = ("Low", "#00aaff", 3)
    INFO = ("Informational", "#888888", 1)
    
    def __init__(self, label: str, color: str, weight: int):
        self.label = label
        self.color = color
        self.weight = weight


@dataclass
class Finding:
    """Security finding"""
    title: str
    severity: SeverityLevel
    category: str
    description: str
    affected_asset: str
    evidence: str = ""
    remediation: str = ""
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    references: List[str] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    raw_output: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ReportConfig:
    """Report configuration"""
    title: str = "Security Assessment Report"
    client_name: str = ""
    assessor_name: str = ""
    assessment_type: str = "Penetration Test"
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    scope: List[str] = field(default_factory=list)
    executive_summary: str = ""
    methodology: str = ""
    include_raw_output: bool = False
    include_screenshots: bool = True
    classification: str = "CONFIDENTIAL"
    logo_path: Optional[str] = None
    custom_css: str = ""


class ReportGenerator:
    """
    Professional security report generator
    Produces reports comparable to Metasploit Pro, Nessus, Burp Suite
    """
    
    # Cyberpunk CSS theme
    CSS_THEME = """
    :root {
        --primary-bg: #0a0e17;
        --secondary-bg: #151b2d;
        --accent: #00ff9d;
        --accent-secondary: #00d4ff;
        --danger: #ff0040;
        --warning: #ffaa00;
        --text-primary: #e0e0e0;
        --text-secondary: #888888;
        --border-color: #2a3548;
    }
    
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }
    
    body {
        font-family: 'Segoe UI', 'Roboto', sans-serif;
        background: var(--primary-bg);
        color: var(--text-primary);
        line-height: 1.6;
    }
    
    .container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 20px;
    }
    
    /* Header */
    .report-header {
        background: linear-gradient(135deg, var(--secondary-bg) 0%, var(--primary-bg) 100%);
        border: 1px solid var(--accent);
        border-radius: 10px;
        padding: 40px;
        margin-bottom: 30px;
        position: relative;
        overflow: hidden;
    }
    
    .report-header::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: linear-gradient(90deg, var(--accent), var(--accent-secondary));
    }
    
    .report-title {
        font-size: 2.5em;
        color: var(--accent);
        margin-bottom: 10px;
        text-transform: uppercase;
        letter-spacing: 2px;
    }
    
    .report-meta {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 20px;
        margin-top: 20px;
    }
    
    .meta-item {
        background: rgba(0, 255, 157, 0.05);
        padding: 15px;
        border-radius: 5px;
        border-left: 3px solid var(--accent);
    }
    
    .meta-label {
        color: var(--text-secondary);
        font-size: 0.9em;
        text-transform: uppercase;
    }
    
    .meta-value {
        color: var(--text-primary);
        font-size: 1.1em;
        font-weight: bold;
    }
    
    /* Classification Banner */
    .classification {
        background: var(--danger);
        color: white;
        text-align: center;
        padding: 10px;
        font-weight: bold;
        letter-spacing: 3px;
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        z-index: 1000;
    }
    
    /* Sections */
    .section {
        background: var(--secondary-bg);
        border: 1px solid var(--border-color);
        border-radius: 10px;
        padding: 30px;
        margin-bottom: 30px;
    }
    
    .section-title {
        color: var(--accent);
        font-size: 1.5em;
        margin-bottom: 20px;
        padding-bottom: 10px;
        border-bottom: 2px solid var(--border-color);
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    .section-title::before {
        content: '►';
        color: var(--accent-secondary);
    }
    
    /* Executive Summary */
    .executive-summary {
        background: linear-gradient(135deg, rgba(0, 255, 157, 0.1) 0%, rgba(0, 212, 255, 0.05) 100%);
        padding: 25px;
        border-radius: 10px;
        border-left: 4px solid var(--accent);
    }
    
    /* Risk Matrix */
    .risk-matrix {
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 10px;
        margin: 20px 0;
    }
    
    .risk-cell {
        padding: 20px;
        border-radius: 8px;
        text-align: center;
        font-size: 1.5em;
        font-weight: bold;
        transition: transform 0.2s;
    }
    
    .risk-cell:hover {
        transform: scale(1.05);
    }
    
    .risk-critical { background: linear-gradient(135deg, #ff0040 0%, #cc0033 100%); }
    .risk-high { background: linear-gradient(135deg, #ff4444 0%, #cc3333 100%); }
    .risk-medium { background: linear-gradient(135deg, #ffaa00 0%, #cc8800 100%); }
    .risk-low { background: linear-gradient(135deg, #00aaff 0%, #0088cc 100%); }
    .risk-info { background: linear-gradient(135deg, #666666 0%, #444444 100%); }
    
    /* Findings */
    .finding {
        background: var(--primary-bg);
        border: 1px solid var(--border-color);
        border-radius: 10px;
        margin-bottom: 20px;
        overflow: hidden;
    }
    
    .finding-header {
        padding: 15px 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        cursor: pointer;
    }
    
    .finding-header.critical { border-left: 4px solid #ff0040; background: rgba(255, 0, 64, 0.1); }
    .finding-header.high { border-left: 4px solid #ff4444; background: rgba(255, 68, 68, 0.1); }
    .finding-header.medium { border-left: 4px solid #ffaa00; background: rgba(255, 170, 0, 0.1); }
    .finding-header.low { border-left: 4px solid #00aaff; background: rgba(0, 170, 255, 0.1); }
    .finding-header.info { border-left: 4px solid #888888; background: rgba(136, 136, 136, 0.1); }
    
    .finding-title {
        font-size: 1.1em;
        font-weight: bold;
    }
    
    .severity-badge {
        padding: 5px 15px;
        border-radius: 20px;
        font-size: 0.85em;
        font-weight: bold;
        text-transform: uppercase;
    }
    
    .severity-critical { background: #ff0040; color: white; }
    .severity-high { background: #ff4444; color: white; }
    .severity-medium { background: #ffaa00; color: black; }
    .severity-low { background: #00aaff; color: white; }
    .severity-info { background: #888888; color: white; }
    
    .finding-body {
        padding: 20px;
        border-top: 1px solid var(--border-color);
    }
    
    .finding-section {
        margin-bottom: 15px;
    }
    
    .finding-section-title {
        color: var(--accent-secondary);
        font-weight: bold;
        margin-bottom: 5px;
        font-size: 0.95em;
    }
    
    /* Code blocks */
    .code-block {
        background: #000;
        border: 1px solid var(--border-color);
        border-radius: 5px;
        padding: 15px;
        font-family: 'Consolas', 'Monaco', monospace;
        font-size: 0.9em;
        overflow-x: auto;
        white-space: pre-wrap;
        color: var(--accent);
    }
    
    /* Tables */
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 15px 0;
    }
    
    th, td {
        padding: 12px;
        text-align: left;
        border: 1px solid var(--border-color);
    }
    
    th {
        background: var(--primary-bg);
        color: var(--accent);
        text-transform: uppercase;
        font-size: 0.9em;
    }
    
    tr:nth-child(even) {
        background: rgba(0, 255, 157, 0.03);
    }
    
    /* Charts */
    .chart-container {
        display: flex;
        justify-content: center;
        gap: 30px;
        flex-wrap: wrap;
        margin: 20px 0;
    }
    
    .pie-chart {
        width: 250px;
        height: 250px;
        position: relative;
    }
    
    .bar-chart {
        display: flex;
        gap: 10px;
        align-items: flex-end;
        height: 200px;
    }
    
    .bar {
        width: 60px;
        display: flex;
        flex-direction: column;
        align-items: center;
    }
    
    .bar-fill {
        width: 100%;
        border-radius: 5px 5px 0 0;
        transition: height 0.5s;
    }
    
    .bar-label {
        margin-top: 10px;
        font-size: 0.8em;
        text-align: center;
    }
    
    /* Print styles */
    @media print {
        body {
            background: white;
            color: black;
        }
        
        .section {
            break-inside: avoid;
        }
        
        .finding {
            break-inside: avoid;
        }
        
        .classification {
            position: static;
            background: #ff0040 !important;
            -webkit-print-color-adjust: exact;
        }
    }
    
    /* Animations */
    @keyframes glow {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.8; }
    }
    
    .glow {
        animation: glow 2s infinite;
    }
    """
    
    def __init__(self, config: Optional[ReportConfig] = None):
        self.config = config or ReportConfig()
        self.findings: List[Finding] = []
        self.scan_results: Dict[str, Any] = {}
        self.methodology_sections: List[Dict] = []
    
    def add_finding(self, finding: Finding):
        """Add a security finding"""
        self.findings.append(finding)
    
    def add_scan_results(self, scanner_type: str, results: Any):
        """Add raw scan results"""
        self.scan_results[scanner_type] = results
    
    def get_severity_stats(self) -> Dict[str, int]:
        """Get finding count by severity"""
        stats = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for finding in self.findings:
            if finding.severity == SeverityLevel.CRITICAL:
                stats["critical"] += 1
            elif finding.severity == SeverityLevel.HIGH:
                stats["high"] += 1
            elif finding.severity == SeverityLevel.MEDIUM:
                stats["medium"] += 1
            elif finding.severity == SeverityLevel.LOW:
                stats["low"] += 1
            else:
                stats["info"] += 1
        
        return stats
    
    def calculate_risk_score(self) -> Tuple[int, str]:
        """Calculate overall risk score"""
        stats = self.get_severity_stats()
        
        score = (
            stats["critical"] * 10 +
            stats["high"] * 8 +
            stats["medium"] * 5 +
            stats["low"] * 3 +
            stats["info"] * 1
        )
        
        if stats["critical"] > 0 or score > 50:
            rating = "CRITICAL"
        elif stats["high"] > 2 or score > 30:
            rating = "HIGH"
        elif stats["medium"] > 3 or score > 15:
            rating = "MEDIUM"
        elif score > 5:
            rating = "LOW"
        else:
            rating = "MINIMAL"
        
        return score, rating
    
    def _generate_svg_pie_chart(self, stats: Dict[str, int]) -> str:
        """Generate SVG pie chart"""
        total = sum(stats.values())
        if total == 0:
            return "<p>No findings</p>"
        
        colors = {
            "critical": "#ff0040",
            "high": "#ff4444",
            "medium": "#ffaa00",
            "low": "#00aaff",
            "info": "#888888"
        }
        
        svg_parts = [
            '<svg viewBox="-1.1 -1.1 2.2 2.2" style="width: 250px; height: 250px; transform: rotate(-90deg);">',
        ]
        
        cumulative = 0
        for severity, count in stats.items():
            if count == 0:
                continue
            
            percentage = count / total
            large_arc = 1 if percentage > 0.5 else 0
            
            x1 = round(cumulative * 3.14159 * 2, 4)
            x2 = round((cumulative + percentage) * 3.14159 * 2, 4)
            
            start_x = round(0.9 * (1 if cumulative == 0 else (1 - 2 * cumulative)), 4)
            start_y = round(0.9 * (0 if cumulative == 0 else (2 * cumulative - 1)), 4)
            
            svg_parts.append(
                f'<circle r="0.45" cx="0" cy="0" fill="transparent" '
                f'stroke="{colors[severity]}" stroke-width="0.9" '
                f'stroke-dasharray="{percentage * 2.827} 2.827" '
                f'stroke-dashoffset="-{cumulative * 2.827}" />'
            )
            
            cumulative += percentage
        
        svg_parts.append('</svg>')
        
        # Legend
        legend_html = '<div style="display: flex; flex-wrap: wrap; gap: 15px; margin-top: 15px;">'
        for severity, count in stats.items():
            if count > 0:
                legend_html += f'''
                <div style="display: flex; align-items: center; gap: 5px;">
                    <span style="width: 12px; height: 12px; background: {colors[severity]}; border-radius: 2px;"></span>
                    <span>{severity.title()}: {count}</span>
                </div>
                '''
        legend_html += '</div>'
        
        return '\n'.join(svg_parts) + legend_html
    
    def _generate_bar_chart(self, stats: Dict[str, int]) -> str:
        """Generate bar chart HTML"""
        max_val = max(stats.values()) if stats.values() else 1
        
        colors = {
            "critical": "#ff0040",
            "high": "#ff4444",
            "medium": "#ffaa00",
            "low": "#00aaff",
            "info": "#888888"
        }
        
        bars = []
        for severity, count in stats.items():
            height = (count / max_val) * 150 if max_val > 0 else 0
            bars.append(f'''
            <div class="bar">
                <div class="bar-fill" style="height: {height}px; background: {colors[severity]};"></div>
                <span>{count}</span>
                <div class="bar-label">{severity.title()}</div>
            </div>
            ''')
        
        return f'<div class="bar-chart">{"".join(bars)}</div>'
    
    def _finding_to_html(self, finding: Finding, index: int) -> str:
        """Convert finding to HTML"""
        severity_class = finding.severity.name.lower()
        
        cve_html = ""
        if finding.cve_ids:
            cve_links = [f'<a href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank">{cve}</a>' 
                        for cve in finding.cve_ids]
            cve_html = f'''
            <div class="finding-section">
                <div class="finding-section-title">CVE References</div>
                <div>{", ".join(cve_links)}</div>
            </div>
            '''
        
        cvss_html = ""
        if finding.cvss_score is not None:
            cvss_html = f'''
            <div class="finding-section">
                <div class="finding-section-title">CVSS Score</div>
                <div><strong>{finding.cvss_score}/10.0</strong></div>
            </div>
            '''
        
        evidence_html = ""
        if finding.evidence:
            evidence_html = f'''
            <div class="finding-section">
                <div class="finding-section-title">Evidence</div>
                <div class="code-block">{html.escape(finding.evidence)}</div>
            </div>
            '''
        
        remediation_html = ""
        if finding.remediation:
            remediation_html = f'''
            <div class="finding-section">
                <div class="finding-section-title">Remediation</div>
                <div>{html.escape(finding.remediation)}</div>
            </div>
            '''
        
        references_html = ""
        if finding.references:
            refs = [f'<li><a href="{ref}" target="_blank">{ref}</a></li>' for ref in finding.references]
            references_html = f'''
            <div class="finding-section">
                <div class="finding-section-title">References</div>
                <ul>{"".join(refs)}</ul>
            </div>
            '''
        
        return f'''
        <div class="finding" id="finding-{index}">
            <div class="finding-header {severity_class}">
                <span class="finding-title">#{index + 1} - {html.escape(finding.title)}</span>
                <span class="severity-badge severity-{severity_class}">{finding.severity.label}</span>
            </div>
            <div class="finding-body">
                <div class="finding-section">
                    <div class="finding-section-title">Category</div>
                    <div>{html.escape(finding.category)}</div>
                </div>
                <div class="finding-section">
                    <div class="finding-section-title">Affected Asset</div>
                    <div>{html.escape(finding.affected_asset)}</div>
                </div>
                <div class="finding-section">
                    <div class="finding-section-title">Description</div>
                    <div>{html.escape(finding.description)}</div>
                </div>
                {cvss_html}
                {cve_html}
                {evidence_html}
                {remediation_html}
                {references_html}
            </div>
        </div>
        '''
    
    def generate_html_report(self) -> str:
        """Generate full HTML report"""
        stats = self.get_severity_stats()
        risk_score, risk_rating = self.calculate_risk_score()
        
        # Sort findings by severity
        sorted_findings = sorted(
            self.findings,
            key=lambda f: f.severity.weight,
            reverse=True
        )
        
        findings_html = "\n".join([
            self._finding_to_html(f, i) 
            for i, f in enumerate(sorted_findings)
        ])
        
        # Generate table of contents
        toc_items = [
            f'<li><a href="#finding-{i}">#{i + 1} - {html.escape(f.title)} ({f.severity.label})</a></li>'
            for i, f in enumerate(sorted_findings)
        ]
        
        # Asset table
        assets = list(set(f.affected_asset for f in self.findings))
        asset_rows = "\n".join([
            f'<tr><td>{html.escape(asset)}</td><td>{sum(1 for f in self.findings if f.affected_asset == asset)}</td></tr>'
            for asset in assets
        ])
        
        report_html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(self.config.title)}</title>
    <style>{self.CSS_THEME}</style>
    <style>{self.config.custom_css}</style>
</head>
<body>
    <div class="classification">{html.escape(self.config.classification)}</div>
    
    <div class="container" style="margin-top: 50px;">
        <!-- Header -->
        <div class="report-header">
            <h1 class="report-title glow">{html.escape(self.config.title)}</h1>
            <p style="color: var(--text-secondary);">Generated by HydraRecon Security Suite</p>
            
            <div class="report-meta">
                <div class="meta-item">
                    <div class="meta-label">Client</div>
                    <div class="meta-value">{html.escape(self.config.client_name or 'N/A')}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Assessment Type</div>
                    <div class="meta-value">{html.escape(self.config.assessment_type)}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Assessor</div>
                    <div class="meta-value">{html.escape(self.config.assessor_name or 'N/A')}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Report Date</div>
                    <div class="meta-value">{datetime.now().strftime('%Y-%m-%d')}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Risk Score</div>
                    <div class="meta-value" style="color: {'#ff0040' if risk_rating in ['CRITICAL', 'HIGH'] else '#ffaa00' if risk_rating == 'MEDIUM' else '#00ff9d'};">{risk_score} ({risk_rating})</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Total Findings</div>
                    <div class="meta-value">{len(self.findings)}</div>
                </div>
            </div>
        </div>
        
        <!-- Executive Summary -->
        <div class="section">
            <h2 class="section-title">Executive Summary</h2>
            <div class="executive-summary">
                {html.escape(self.config.executive_summary) if self.config.executive_summary else '''
                <p>This security assessment identified <strong>{} findings</strong> across the target environment.
                The overall risk level is <strong style="color: {}">{}</strong>.</p>
                <p>Critical attention is required for {} critical and {} high severity findings that could lead to 
                significant security breaches if exploited.</p>
                '''.format(
                    len(self.findings),
                    '#ff0040' if risk_rating in ['CRITICAL', 'HIGH'] else '#ffaa00' if risk_rating == 'MEDIUM' else '#00ff9d',
                    risk_rating,
                    stats['critical'],
                    stats['high']
                )}
            </div>
        </div>
        
        <!-- Risk Overview -->
        <div class="section">
            <h2 class="section-title">Risk Overview</h2>
            <div class="chart-container">
                <div>
                    <h3 style="text-align: center; color: var(--accent-secondary);">Severity Distribution</h3>
                    {self._generate_svg_pie_chart(stats)}
                </div>
                <div>
                    <h3 style="text-align: center; color: var(--accent-secondary);">Finding Count by Severity</h3>
                    {self._generate_bar_chart(stats)}
                </div>
            </div>
            
            <div class="risk-matrix" style="margin-top: 30px;">
                <div class="risk-cell risk-critical">{stats['critical']}<br><small>Critical</small></div>
                <div class="risk-cell risk-high">{stats['high']}<br><small>High</small></div>
                <div class="risk-cell risk-medium">{stats['medium']}<br><small>Medium</small></div>
                <div class="risk-cell risk-low">{stats['low']}<br><small>Low</small></div>
                <div class="risk-cell risk-info">{stats['info']}<br><small>Info</small></div>
            </div>
        </div>
        
        <!-- Affected Assets -->
        <div class="section">
            <h2 class="section-title">Affected Assets</h2>
            <table>
                <thead>
                    <tr>
                        <th>Asset</th>
                        <th>Finding Count</th>
                    </tr>
                </thead>
                <tbody>
                    {asset_rows if asset_rows else '<tr><td colspan="2">No assets found</td></tr>'}
                </tbody>
            </table>
        </div>
        
        <!-- Table of Contents -->
        <div class="section">
            <h2 class="section-title">Table of Contents</h2>
            <ol style="columns: 2; column-gap: 40px;">
                {"".join(toc_items) if toc_items else '<li>No findings</li>'}
            </ol>
        </div>
        
        <!-- Detailed Findings -->
        <div class="section">
            <h2 class="section-title">Detailed Findings</h2>
            {findings_html if findings_html else '<p>No findings to report.</p>'}
        </div>
        
        <!-- Methodology -->
        <div class="section">
            <h2 class="section-title">Methodology</h2>
            <div>
                {html.escape(self.config.methodology) if self.config.methodology else '''
                <p>The assessment was conducted using the following methodology:</p>
                <ol>
                    <li><strong>Reconnaissance</strong> - Target enumeration and information gathering using OSINT techniques</li>
                    <li><strong>Scanning</strong> - Network and port scanning with service identification</li>
                    <li><strong>Vulnerability Assessment</strong> - Automated and manual vulnerability scanning</li>
                    <li><strong>Exploitation</strong> - Attempted exploitation of identified vulnerabilities</li>
                    <li><strong>Post-Exploitation</strong> - Assessment of impact and lateral movement potential</li>
                    <li><strong>Reporting</strong> - Documentation of findings with remediation recommendations</li>
                </ol>
                '''}
            </div>
        </div>
        
        <!-- Footer -->
        <div style="text-align: center; padding: 30px; color: var(--text-secondary);">
            <p>Generated by <span style="color: var(--accent);">HydraRecon Security Suite</span></p>
            <p>Report ID: {hashlib.md5(str(datetime.now()).encode()).hexdigest()[:16].upper()}</p>
            <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
    </div>
    
    <script>
        // Interactive finding toggles
        document.querySelectorAll('.finding-header').forEach(header => {{
            header.addEventListener('click', () => {{
                const body = header.nextElementSibling;
                body.style.display = body.style.display === 'none' ? 'block' : 'none';
            }});
        }});
    </script>
</body>
</html>'''
        
        return report_html
    
    def generate_json_report(self) -> str:
        """Generate JSON report"""
        stats = self.get_severity_stats()
        risk_score, risk_rating = self.calculate_risk_score()
        
        report_data = {
            "report_metadata": {
                "title": self.config.title,
                "client_name": self.config.client_name,
                "assessor_name": self.config.assessor_name,
                "assessment_type": self.config.assessment_type,
                "generated_at": datetime.now().isoformat(),
                "classification": self.config.classification,
            },
            "summary": {
                "total_findings": len(self.findings),
                "risk_score": risk_score,
                "risk_rating": risk_rating,
                "severity_breakdown": stats,
            },
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.label,
                    "category": f.category,
                    "description": f.description,
                    "affected_asset": f.affected_asset,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "cve_ids": f.cve_ids,
                    "cvss_score": f.cvss_score,
                    "references": f.references,
                    "timestamp": f.timestamp.isoformat(),
                }
                for f in self.findings
            ],
            "scan_results": self.scan_results,
        }
        
        return json.dumps(report_data, indent=2)
    
    def generate_markdown_report(self) -> str:
        """Generate Markdown report"""
        stats = self.get_severity_stats()
        risk_score, risk_rating = self.calculate_risk_score()
        
        lines = [
            f"# {self.config.title}",
            "",
            f"**Classification:** {self.config.classification}",
            "",
            "## Report Information",
            "",
            f"- **Client:** {self.config.client_name or 'N/A'}",
            f"- **Assessor:** {self.config.assessor_name or 'N/A'}",
            f"- **Assessment Type:** {self.config.assessment_type}",
            f"- **Date:** {datetime.now().strftime('%Y-%m-%d')}",
            f"- **Risk Score:** {risk_score} ({risk_rating})",
            "",
            "## Executive Summary",
            "",
            self.config.executive_summary or f"This security assessment identified **{len(self.findings)} findings**. The overall risk level is **{risk_rating}**.",
            "",
            "## Severity Breakdown",
            "",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| Critical | {stats['critical']} |",
            f"| High | {stats['high']} |",
            f"| Medium | {stats['medium']} |",
            f"| Low | {stats['low']} |",
            f"| Info | {stats['info']} |",
            "",
            "## Detailed Findings",
            "",
        ]
        
        for i, finding in enumerate(sorted(self.findings, key=lambda f: f.severity.weight, reverse=True)):
            lines.extend([
                f"### {i + 1}. {finding.title}",
                "",
                f"**Severity:** {finding.severity.label}",
                f"**Category:** {finding.category}",
                f"**Affected Asset:** {finding.affected_asset}",
                "",
                "**Description:**",
                finding.description,
                "",
            ])
            
            if finding.evidence:
                lines.extend([
                    "**Evidence:**",
                    "```",
                    finding.evidence,
                    "```",
                    "",
                ])
            
            if finding.remediation:
                lines.extend([
                    "**Remediation:**",
                    finding.remediation,
                    "",
                ])
            
            if finding.cve_ids:
                lines.extend([
                    "**CVE References:** " + ", ".join(finding.cve_ids),
                    "",
                ])
            
            lines.append("---")
            lines.append("")
        
        lines.extend([
            "",
            "---",
            f"*Report generated by HydraRecon Security Suite - {datetime.now().isoformat()}*",
        ])
        
        return "\n".join(lines)
    
    def save_report(self, output_path: str, format: ReportFormat = ReportFormat.HTML) -> str:
        """Save report to file"""
        if format == ReportFormat.HTML:
            content = self.generate_html_report()
            ext = ".html"
        elif format == ReportFormat.JSON:
            content = self.generate_json_report()
            ext = ".json"
        elif format == ReportFormat.MARKDOWN:
            content = self.generate_markdown_report()
            ext = ".md"
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        if not output_path.endswith(ext):
            output_path += ext
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return output_path


# Convenience function for quick report generation
def create_quick_report(findings_data: List[Dict], 
                       title: str = "Security Assessment Report",
                       output_path: str = None) -> str:
    """Create a quick report from finding dictionaries"""
    config = ReportConfig(title=title)
    generator = ReportGenerator(config)
    
    severity_map = {
        "critical": SeverityLevel.CRITICAL,
        "high": SeverityLevel.HIGH,
        "medium": SeverityLevel.MEDIUM,
        "low": SeverityLevel.LOW,
        "info": SeverityLevel.INFO,
    }
    
    for data in findings_data:
        finding = Finding(
            title=data.get("title", "Unknown"),
            severity=severity_map.get(data.get("severity", "info").lower(), SeverityLevel.INFO),
            category=data.get("category", "General"),
            description=data.get("description", ""),
            affected_asset=data.get("asset", data.get("affected_asset", "Unknown")),
            evidence=data.get("evidence", ""),
            remediation=data.get("remediation", ""),
            cve_ids=data.get("cve_ids", []),
            cvss_score=data.get("cvss_score"),
        )
        generator.add_finding(finding)
    
    if output_path:
        return generator.save_report(output_path)
    else:
        return generator.generate_html_report()
