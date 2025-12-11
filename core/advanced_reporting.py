"""
HydraRecon Advanced Reporting Engine
Comprehensive security report generation with multiple formats
"""

import asyncio
import hashlib
import json
import time
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import html
import re


class ReportFormat(Enum):
    """Supported report formats"""
    PDF = "pdf"
    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    DOCX = "docx"
    XLSX = "xlsx"
    STIX = "stix"
    SARIF = "sarif"
    JIRA = "jira"
    SLACK = "slack"
    ASCIIDOC = "asciidoc"


class ReportType(Enum):
    """Types of security reports"""
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAIL = "technical_detail"
    VULNERABILITY = "vulnerability"
    PENETRATION_TEST = "penetration_test"
    COMPLIANCE = "compliance"
    INCIDENT_RESPONSE = "incident_response"
    THREAT_INTELLIGENCE = "threat_intelligence"
    RISK_ASSESSMENT = "risk_assessment"
    REMEDIATION = "remediation"
    AUDIT = "audit"
    FORENSICS = "forensics"


class SeverityLevel(Enum):
    """Severity levels with colors"""
    CRITICAL = ("critical", "#dc3545", 10)
    HIGH = ("high", "#fd7e14", 7)
    MEDIUM = ("medium", "#ffc107", 4)
    LOW = ("low", "#17a2b8", 1)
    INFO = ("info", "#6c757d", 0)
    
    @property
    def name_str(self) -> str:
        return self.value[0]
    
    @property
    def color(self) -> str:
        return self.value[1]
    
    @property
    def score(self) -> int:
        return self.value[2]


@dataclass
class ReportSection:
    """Report section with content"""
    section_id: str
    title: str
    content: str
    order: int = 0
    subsections: List['ReportSection'] = field(default_factory=list)
    charts: List[Dict] = field(default_factory=list)
    tables: List[Dict] = field(default_factory=list)
    images: List[Dict] = field(default_factory=list)
    code_blocks: List[Dict] = field(default_factory=list)
    is_appendix: bool = False


@dataclass
class Finding:
    """Security finding/vulnerability"""
    finding_id: str
    title: str
    severity: SeverityLevel
    description: str
    affected_assets: List[str]
    technical_details: str
    evidence: List[Dict]
    remediation: str
    references: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    status: str = "open"
    discovered_date: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            'finding_id': self.finding_id,
            'title': self.title,
            'severity': self.severity.name_str,
            'severity_color': self.severity.color,
            'severity_score': self.severity.score,
            'description': self.description,
            'affected_assets': self.affected_assets,
            'technical_details': self.technical_details,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'references': self.references,
            'cve_ids': self.cve_ids,
            'cwe_ids': self.cwe_ids,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'status': self.status,
            'discovered_date': self.discovered_date.isoformat()
        }


@dataclass
class ReportMetadata:
    """Report metadata"""
    report_id: str
    title: str
    report_type: ReportType
    created_date: datetime
    author: str
    organization: str
    classification: str = "Confidential"
    version: str = "1.0"
    target: str = ""
    scope: str = ""
    methodology: str = ""
    executive_summary: str = ""
    custom_fields: Dict = field(default_factory=dict)


class ChartGenerator:
    """Generate charts for reports"""
    
    @staticmethod
    def severity_pie_chart(findings: List[Finding]) -> Dict:
        """Generate severity distribution pie chart data"""
        distribution = defaultdict(int)
        for finding in findings:
            distribution[finding.severity.name_str] += 1
        
        return {
            'type': 'pie',
            'title': 'Findings by Severity',
            'data': [
                {'label': sev, 'value': count, 'color': SeverityLevel[sev.upper()].color}
                for sev, count in distribution.items()
            ]
        }
    
    @staticmethod
    def timeline_chart(findings: List[Finding]) -> Dict:
        """Generate findings timeline chart"""
        by_date = defaultdict(int)
        for finding in findings:
            date_str = finding.discovered_date.strftime('%Y-%m-%d')
            by_date[date_str] += 1
        
        sorted_dates = sorted(by_date.items())
        
        return {
            'type': 'line',
            'title': 'Findings Over Time',
            'labels': [d[0] for d in sorted_dates],
            'datasets': [{
                'label': 'Findings',
                'data': [d[1] for d in sorted_dates]
            }]
        }
    
    @staticmethod
    def category_bar_chart(findings: List[Finding]) -> Dict:
        """Generate findings by category bar chart"""
        by_cwe = defaultdict(int)
        for finding in findings:
            for cwe in finding.cwe_ids[:1]:  # Primary CWE
                by_cwe[cwe] += 1
        
        return {
            'type': 'bar',
            'title': 'Findings by Category (CWE)',
            'labels': list(by_cwe.keys()),
            'datasets': [{
                'label': 'Count',
                'data': list(by_cwe.values())
            }]
        }
    
    @staticmethod
    def risk_matrix(findings: List[Finding]) -> Dict:
        """Generate risk matrix visualization data"""
        matrix = [[0] * 5 for _ in range(5)]  # 5x5 matrix
        
        # Map severity to impact (y-axis) and assume likelihood based on CVSS
        for finding in findings:
            impact = min(4, finding.severity.score // 3)
            likelihood = min(4, int((finding.cvss_score or 5) / 2))
            matrix[4 - impact][likelihood] += 1
        
        return {
            'type': 'heatmap',
            'title': 'Risk Matrix',
            'x_labels': ['Rare', 'Unlikely', 'Possible', 'Likely', 'Almost Certain'],
            'y_labels': ['Negligible', 'Minor', 'Moderate', 'Major', 'Severe'],
            'data': matrix
        }


class HTMLReportGenerator:
    """Generate HTML reports with modern styling"""
    
    def __init__(self):
        self.chart_generator = ChartGenerator()
    
    def generate(self, metadata: ReportMetadata, sections: List[ReportSection],
                findings: List[Finding]) -> str:
        """Generate complete HTML report"""
        css = self._get_css()
        header = self._generate_header(metadata)
        toc = self._generate_toc(sections)
        content = self._generate_content(sections)
        findings_section = self._generate_findings(findings)
        charts = self._generate_charts(findings)
        footer = self._generate_footer(metadata)
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(metadata.title)}</title>
    <style>{css}</style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="report-container">
        {header}
        <div class="toc">
            <h2>Table of Contents</h2>
            {toc}
        </div>
        {charts}
        {content}
        {findings_section}
        {footer}
    </div>
    <script>{self._get_chart_js(findings)}</script>
</body>
</html>"""
        
        return html_content
    
    def _get_css(self) -> str:
        """Get report CSS styles"""
        return """
        :root {
            --primary-color: #00ff88;
            --secondary-color: #0a0a0a;
            --text-color: #ffffff;
            --bg-color: #0d0d0d;
            --card-bg: #1a1a1a;
            --border-color: #333;
            --critical-color: #dc3545;
            --high-color: #fd7e14;
            --medium-color: #ffc107;
            --low-color: #17a2b8;
            --info-color: #6c757d;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
        }
        
        .report-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px;
        }
        
        .report-header {
            background: linear-gradient(135deg, var(--card-bg) 0%, #252525 100%);
            border: 1px solid var(--primary-color);
            border-radius: 10px;
            padding: 40px;
            margin-bottom: 40px;
            text-align: center;
        }
        
        .report-header h1 {
            color: var(--primary-color);
            font-size: 2.5em;
            margin-bottom: 20px;
            text-shadow: 0 0 10px rgba(0, 255, 136, 0.3);
        }
        
        .report-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
        }
        
        .meta-item {
            text-align: left;
        }
        
        .meta-label {
            color: var(--primary-color);
            font-size: 0.85em;
            text-transform: uppercase;
        }
        
        .meta-value {
            font-size: 1.1em;
            margin-top: 5px;
        }
        
        .classification-badge {
            display: inline-block;
            padding: 5px 15px;
            background: var(--critical-color);
            border-radius: 5px;
            font-weight: bold;
            margin-top: 20px;
        }
        
        .toc {
            background: var(--card-bg);
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 40px;
        }
        
        .toc h2 {
            color: var(--primary-color);
            margin-bottom: 20px;
        }
        
        .toc ul {
            list-style: none;
        }
        
        .toc li {
            padding: 8px 0;
            border-bottom: 1px solid var(--border-color);
        }
        
        .toc a {
            color: var(--text-color);
            text-decoration: none;
            transition: color 0.3s;
        }
        
        .toc a:hover {
            color: var(--primary-color);
        }
        
        .section {
            background: var(--card-bg);
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
        }
        
        .section h2 {
            color: var(--primary-color);
            border-bottom: 2px solid var(--primary-color);
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        .section h3 {
            color: #ccc;
            margin: 20px 0 10px 0;
        }
        
        .charts-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-bottom: 40px;
        }
        
        .chart-card {
            background: var(--card-bg);
            border-radius: 10px;
            padding: 20px;
        }
        
        .chart-card h3 {
            color: var(--primary-color);
            margin-bottom: 20px;
            text-align: center;
        }
        
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .findings-table th,
        .findings-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        
        .findings-table th {
            background: var(--secondary-color);
            color: var(--primary-color);
            font-weight: 600;
        }
        
        .findings-table tr:hover {
            background: rgba(0, 255, 136, 0.05);
        }
        
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.85em;
            text-transform: uppercase;
        }
        
        .severity-critical { background: var(--critical-color); }
        .severity-high { background: var(--high-color); color: #000; }
        .severity-medium { background: var(--medium-color); color: #000; }
        .severity-low { background: var(--low-color); }
        .severity-info { background: var(--info-color); }
        
        .finding-detail {
            background: var(--card-bg);
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            border-left: 4px solid var(--primary-color);
        }
        
        .finding-detail h4 {
            color: var(--primary-color);
            margin-bottom: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .finding-section {
            margin: 15px 0;
        }
        
        .finding-section-title {
            color: #888;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 5px;
        }
        
        .code-block {
            background: #0a0a0a;
            border: 1px solid var(--border-color);
            border-radius: 5px;
            padding: 15px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
        }
        
        .evidence-item {
            background: rgba(0, 255, 136, 0.05);
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
        }
        
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--card-bg);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: var(--primary-color);
        }
        
        .stat-label {
            color: #888;
            margin-top: 5px;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: #666;
            border-top: 1px solid var(--border-color);
            margin-top: 40px;
        }
        
        @media print {
            body { background: white; color: black; }
            .report-container { max-width: 100%; }
            .section { break-inside: avoid; }
        }
        """
    
    def _generate_header(self, metadata: ReportMetadata) -> str:
        """Generate report header"""
        return f"""
        <div class="report-header">
            <h1>{html.escape(metadata.title)}</h1>
            <p>{html.escape(metadata.executive_summary[:200])}...</p>
            <div class="classification-badge">{html.escape(metadata.classification)}</div>
            <div class="report-meta">
                <div class="meta-item">
                    <div class="meta-label">Report ID</div>
                    <div class="meta-value">{html.escape(metadata.report_id)}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Author</div>
                    <div class="meta-value">{html.escape(metadata.author)}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Organization</div>
                    <div class="meta-value">{html.escape(metadata.organization)}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Date</div>
                    <div class="meta-value">{metadata.created_date.strftime('%Y-%m-%d')}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Target</div>
                    <div class="meta-value">{html.escape(metadata.target)}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Version</div>
                    <div class="meta-value">{html.escape(metadata.version)}</div>
                </div>
            </div>
        </div>
        """
    
    def _generate_toc(self, sections: List[ReportSection]) -> str:
        """Generate table of contents"""
        items = []
        for section in sorted(sections, key=lambda s: s.order):
            items.append(f'<li><a href="#{section.section_id}">{html.escape(section.title)}</a></li>')
            for subsection in section.subsections:
                items.append(f'<li style="padding-left: 20px;"><a href="#{subsection.section_id}">↳ {html.escape(subsection.title)}</a></li>')
        
        return f'<ul>{"".join(items)}</ul>'
    
    def _generate_content(self, sections: List[ReportSection]) -> str:
        """Generate main content sections"""
        content_html = []
        
        for section in sorted(sections, key=lambda s: s.order):
            section_html = f"""
            <div class="section" id="{section.section_id}">
                <h2>{html.escape(section.title)}</h2>
                <div>{section.content}</div>
            """
            
            # Add tables
            for table in section.tables:
                section_html += self._render_table(table)
            
            # Add code blocks
            for code_block in section.code_blocks:
                section_html += f"""
                <div class="code-block">
                    <pre>{html.escape(code_block.get('code', ''))}</pre>
                </div>
                """
            
            # Add subsections
            for subsection in section.subsections:
                section_html += f"""
                <div id="{subsection.section_id}">
                    <h3>{html.escape(subsection.title)}</h3>
                    <div>{subsection.content}</div>
                </div>
                """
            
            section_html += "</div>"
            content_html.append(section_html)
        
        return "".join(content_html)
    
    def _generate_findings(self, findings: List[Finding]) -> str:
        """Generate findings section"""
        if not findings:
            return ""
        
        # Summary stats
        severity_counts = defaultdict(int)
        for finding in findings:
            severity_counts[finding.severity.name_str] += 1
        
        stats_html = """
        <div class="summary-stats">
        """
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(sev, 0)
            stats_html += f"""
            <div class="stat-card">
                <div class="stat-value" style="color: {SeverityLevel[sev.upper()].color}">{count}</div>
                <div class="stat-label">{sev.capitalize()}</div>
            </div>
            """
        stats_html += "</div>"
        
        # Findings table
        table_rows = []
        for finding in sorted(findings, key=lambda f: f.severity.score, reverse=True):
            table_rows.append(f"""
            <tr>
                <td>{html.escape(finding.finding_id)}</td>
                <td>{html.escape(finding.title)}</td>
                <td><span class="severity-badge severity-{finding.severity.name_str}">{finding.severity.name_str}</span></td>
                <td>{finding.cvss_score or 'N/A'}</td>
                <td>{html.escape(finding.status)}</td>
            </tr>
            """)
        
        # Detailed findings
        details_html = []
        for finding in sorted(findings, key=lambda f: f.severity.score, reverse=True):
            evidence_html = ""
            for ev in finding.evidence:
                evidence_html += f"""
                <div class="evidence-item">
                    <strong>{html.escape(ev.get('type', 'Evidence'))}:</strong>
                    <pre>{html.escape(str(ev.get('data', '')))}</pre>
                </div>
                """
            
            details_html.append(f"""
            <div class="finding-detail">
                <h4>
                    <span>{html.escape(finding.title)}</span>
                    <span class="severity-badge severity-{finding.severity.name_str}">{finding.severity.name_str}</span>
                </h4>
                
                <div class="finding-section">
                    <div class="finding-section-title">Description</div>
                    <p>{html.escape(finding.description)}</p>
                </div>
                
                <div class="finding-section">
                    <div class="finding-section-title">Affected Assets</div>
                    <p>{', '.join(html.escape(a) for a in finding.affected_assets)}</p>
                </div>
                
                <div class="finding-section">
                    <div class="finding-section-title">Technical Details</div>
                    <div class="code-block"><pre>{html.escape(finding.technical_details)}</pre></div>
                </div>
                
                <div class="finding-section">
                    <div class="finding-section-title">Evidence</div>
                    {evidence_html}
                </div>
                
                <div class="finding-section">
                    <div class="finding-section-title">Remediation</div>
                    <p>{html.escape(finding.remediation)}</p>
                </div>
                
                <div class="finding-section">
                    <div class="finding-section-title">References</div>
                    <ul>
                        {''.join(f"<li><a href='{html.escape(ref)}'>{html.escape(ref)}</a></li>" for ref in finding.references)}
                    </ul>
                </div>
            </div>
            """)
        
        return f"""
        <div class="section" id="findings">
            <h2>Security Findings</h2>
            {stats_html}
            
            <h3>Summary Table</h3>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>CVSS</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(table_rows)}
                </tbody>
            </table>
            
            <h3>Detailed Findings</h3>
            {''.join(details_html)}
        </div>
        """
    
    def _generate_charts(self, findings: List[Finding]) -> str:
        """Generate charts section"""
        if not findings:
            return ""
        
        return """
        <div class="charts-container">
            <div class="chart-card">
                <h3>Severity Distribution</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>Findings Over Time</h3>
                <canvas id="timelineChart"></canvas>
            </div>
        </div>
        """
    
    def _get_chart_js(self, findings: List[Finding]) -> str:
        """Generate Chart.js JavaScript"""
        severity_data = self.chart_generator.severity_pie_chart(findings)
        timeline_data = self.chart_generator.timeline_chart(findings)
        
        return f"""
        // Severity Pie Chart
        new Chart(document.getElementById('severityChart'), {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps([d['label'] for d in severity_data['data']])},
                datasets: [{{
                    data: {json.dumps([d['value'] for d in severity_data['data']])},
                    backgroundColor: {json.dumps([d['color'] for d in severity_data['data']])}
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{ color: '#fff' }}
                    }}
                }}
            }}
        }});
        
        // Timeline Chart
        new Chart(document.getElementById('timelineChart'), {{
            type: 'line',
            data: {{
                labels: {json.dumps(timeline_data['labels'])},
                datasets: [{{
                    label: 'Findings',
                    data: {json.dumps(timeline_data['datasets'][0]['data'])},
                    borderColor: '#00ff88',
                    backgroundColor: 'rgba(0, 255, 136, 0.1)',
                    fill: true,
                    tension: 0.4
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    x: {{ ticks: {{ color: '#888' }} }},
                    y: {{ ticks: {{ color: '#888' }} }}
                }},
                plugins: {{
                    legend: {{
                        labels: {{ color: '#fff' }}
                    }}
                }}
            }}
        }});
        """
    
    def _render_table(self, table: Dict) -> str:
        """Render a table"""
        headers = table.get('headers', [])
        rows = table.get('rows', [])
        
        header_html = ''.join(f'<th>{html.escape(str(h))}</th>' for h in headers)
        rows_html = ''
        for row in rows:
            cells = ''.join(f'<td>{html.escape(str(c))}</td>' for c in row)
            rows_html += f'<tr>{cells}</tr>'
        
        return f"""
        <table class="findings-table">
            <thead><tr>{header_html}</tr></thead>
            <tbody>{rows_html}</tbody>
        </table>
        """
    
    def _generate_footer(self, metadata: ReportMetadata) -> str:
        """Generate report footer"""
        return f"""
        <div class="footer">
            <p>Report generated by HydraRecon Security Platform</p>
            <p>{html.escape(metadata.organization)} - {metadata.created_date.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Report ID: {html.escape(metadata.report_id)} | Version: {html.escape(metadata.version)}</p>
        </div>
        """


class MarkdownReportGenerator:
    """Generate Markdown reports"""
    
    def generate(self, metadata: ReportMetadata, sections: List[ReportSection],
                findings: List[Finding]) -> str:
        """Generate complete Markdown report"""
        lines = [
            f"# {metadata.title}",
            "",
            f"**Report ID:** {metadata.report_id}",
            f"**Author:** {metadata.author}",
            f"**Organization:** {metadata.organization}",
            f"**Date:** {metadata.created_date.strftime('%Y-%m-%d')}",
            f"**Classification:** {metadata.classification}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            metadata.executive_summary,
            "",
            "---",
            "",
            "## Table of Contents",
            ""
        ]
        
        # TOC
        for i, section in enumerate(sorted(sections, key=lambda s: s.order), 1):
            lines.append(f"{i}. [{section.title}](#{section.section_id})")
        
        lines.extend(["", "---", ""])
        
        # Sections
        for section in sorted(sections, key=lambda s: s.order):
            lines.extend([
                f"## {section.title}",
                "",
                section.content,
                ""
            ])
            
            for subsection in section.subsections:
                lines.extend([
                    f"### {subsection.title}",
                    "",
                    subsection.content,
                    ""
                ])
        
        # Findings
        if findings:
            lines.extend([
                "---",
                "",
                "## Security Findings",
                "",
                "| ID | Title | Severity | CVSS | Status |",
                "|---|---|---|---|---|"
            ])
            
            for finding in sorted(findings, key=lambda f: f.severity.score, reverse=True):
                lines.append(f"| {finding.finding_id} | {finding.title} | {finding.severity.name_str} | {finding.cvss_score or 'N/A'} | {finding.status} |")
            
            lines.extend(["", "### Detailed Findings", ""])
            
            for finding in sorted(findings, key=lambda f: f.severity.score, reverse=True):
                lines.extend([
                    f"#### {finding.finding_id}: {finding.title}",
                    "",
                    f"**Severity:** {finding.severity.name_str}",
                    f"**CVSS Score:** {finding.cvss_score or 'N/A'}",
                    "",
                    "**Description:**",
                    finding.description,
                    "",
                    "**Affected Assets:**",
                    ", ".join(finding.affected_assets),
                    "",
                    "**Technical Details:**",
                    "```",
                    finding.technical_details,
                    "```",
                    "",
                    "**Remediation:**",
                    finding.remediation,
                    "",
                    "---",
                    ""
                ])
        
        # Footer
        lines.extend([
            "",
            "---",
            "",
            f"*Report generated by HydraRecon Security Platform on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
        ])
        
        return "\n".join(lines)


class JSONReportGenerator:
    """Generate JSON reports"""
    
    def generate(self, metadata: ReportMetadata, sections: List[ReportSection],
                findings: List[Finding]) -> str:
        """Generate complete JSON report"""
        report = {
            'metadata': {
                'report_id': metadata.report_id,
                'title': metadata.title,
                'report_type': metadata.report_type.value,
                'created_date': metadata.created_date.isoformat(),
                'author': metadata.author,
                'organization': metadata.organization,
                'classification': metadata.classification,
                'version': metadata.version,
                'target': metadata.target,
                'scope': metadata.scope,
                'methodology': metadata.methodology,
                'executive_summary': metadata.executive_summary
            },
            'sections': [
                {
                    'section_id': s.section_id,
                    'title': s.title,
                    'content': s.content,
                    'order': s.order,
                    'subsections': [
                        {
                            'section_id': ss.section_id,
                            'title': ss.title,
                            'content': ss.content
                        }
                        for ss in s.subsections
                    ]
                }
                for s in sections
            ],
            'findings': [f.to_dict() for f in findings],
            'statistics': {
                'total_findings': len(findings),
                'by_severity': {
                    sev.name_str: sum(1 for f in findings if f.severity == sev)
                    for sev in SeverityLevel
                },
                'open_findings': sum(1 for f in findings if f.status == 'open'),
                'closed_findings': sum(1 for f in findings if f.status == 'closed')
            }
        }
        
        return json.dumps(report, indent=2)


class SARIFReportGenerator:
    """Generate SARIF (Static Analysis Results Interchange Format) reports"""
    
    def generate(self, metadata: ReportMetadata, sections: List[ReportSection],
                findings: List[Finding]) -> str:
        """Generate SARIF report"""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "HydraRecon",
                            "version": "1.0.0",
                            "informationUri": "https://hydrarecon.io",
                            "rules": [
                                {
                                    "id": f.finding_id,
                                    "name": f.title,
                                    "shortDescription": {"text": f.title},
                                    "fullDescription": {"text": f.description},
                                    "help": {"text": f.remediation},
                                    "properties": {
                                        "severity": f.severity.name_str,
                                        "cwe": f.cwe_ids
                                    }
                                }
                                for f in findings
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": f.finding_id,
                            "level": self._severity_to_level(f.severity),
                            "message": {"text": f.description},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": asset}
                                    }
                                }
                                for asset in f.affected_assets
                            ]
                        }
                        for f in findings
                    ]
                }
            ]
        }
        
        return json.dumps(sarif, indent=2)
    
    def _severity_to_level(self, severity: SeverityLevel) -> str:
        """Convert severity to SARIF level"""
        mapping = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'none'
        }
        return mapping.get(severity.name_str, 'warning')


class AdvancedReportingEngine:
    """
    Main advanced reporting engine
    Supports multiple formats and report types
    """
    
    def __init__(self):
        self.generators = {
            ReportFormat.HTML: HTMLReportGenerator(),
            ReportFormat.MARKDOWN: MarkdownReportGenerator(),
            ReportFormat.JSON: JSONReportGenerator(),
            ReportFormat.SARIF: SARIFReportGenerator()
        }
        
        self.templates: Dict[ReportType, Dict] = {}
        self.custom_generators: Dict[ReportFormat, Callable] = {}
    
    def generate_report(self, metadata: ReportMetadata, 
                       sections: List[ReportSection],
                       findings: List[Finding],
                       format_type: ReportFormat = ReportFormat.HTML) -> str:
        """Generate a report in the specified format"""
        generator = self.generators.get(format_type)
        
        if generator:
            return generator.generate(metadata, sections, findings)
        
        if format_type in self.custom_generators:
            return self.custom_generators[format_type](metadata, sections, findings)
        
        # Default to JSON
        return self.generators[ReportFormat.JSON].generate(metadata, sections, findings)
    
    def create_pentest_report(self, target: str, findings: List[Finding],
                             author: str = "Security Team",
                             organization: str = "HydraRecon") -> Dict:
        """Create a penetration testing report"""
        metadata = ReportMetadata(
            report_id=hashlib.sha256(f"{target}-{time.time()}".encode()).hexdigest()[:16],
            title=f"Penetration Test Report - {target}",
            report_type=ReportType.PENETRATION_TEST,
            created_date=datetime.now(),
            author=author,
            organization=organization,
            target=target,
            scope=f"Full security assessment of {target}",
            methodology="OWASP Testing Guide, PTES",
            executive_summary=self._generate_executive_summary(findings)
        )
        
        sections = [
            ReportSection(
                section_id="intro",
                title="Introduction",
                content=f"This report presents the findings from a penetration test conducted against {target}.",
                order=1
            ),
            ReportSection(
                section_id="scope",
                title="Scope and Methodology",
                content=f"The assessment covered {target} using industry-standard methodologies including OWASP Testing Guide and PTES.",
                order=2
            ),
            ReportSection(
                section_id="summary",
                title="Executive Summary",
                content=metadata.executive_summary,
                order=3
            )
        ]
        
        return {
            'metadata': metadata,
            'sections': sections,
            'findings': findings
        }
    
    def create_compliance_report(self, framework: str, controls: List[Dict],
                                findings: List[Finding]) -> Dict:
        """Create a compliance assessment report"""
        metadata = ReportMetadata(
            report_id=hashlib.sha256(f"compliance-{framework}-{time.time()}".encode()).hexdigest()[:16],
            title=f"{framework} Compliance Assessment Report",
            report_type=ReportType.COMPLIANCE,
            created_date=datetime.now(),
            author="Compliance Team",
            organization="HydraRecon",
            scope=f"{framework} compliance assessment",
            methodology=f"{framework} control framework"
        )
        
        # Calculate compliance percentage
        compliant = sum(1 for c in controls if c.get('status') == 'compliant')
        total = len(controls)
        compliance_pct = (compliant / total * 100) if total > 0 else 0
        
        metadata.executive_summary = f"Overall compliance with {framework}: {compliance_pct:.1f}%"
        
        sections = [
            ReportSection(
                section_id="overview",
                title="Compliance Overview",
                content=f"This report assesses compliance with {framework} framework.",
                order=1,
                tables=[{
                    'headers': ['Control ID', 'Description', 'Status', 'Notes'],
                    'rows': [
                        [c.get('id', ''), c.get('description', ''), c.get('status', ''), c.get('notes', '')]
                        for c in controls
                    ]
                }]
            )
        ]
        
        return {
            'metadata': metadata,
            'sections': sections,
            'findings': findings,
            'controls': controls,
            'compliance_percentage': compliance_pct
        }
    
    def _generate_executive_summary(self, findings: List[Finding]) -> str:
        """Generate executive summary from findings"""
        if not findings:
            return "No security findings were identified during this assessment."
        
        severity_counts = defaultdict(int)
        for f in findings:
            severity_counts[f.severity.name_str] += 1
        
        summary = f"""During this security assessment, a total of {len(findings)} security findings were identified:

- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}
- Informational: {severity_counts['info']}

"""
        
        if severity_counts['critical'] > 0:
            summary += "Immediate attention is required to address the critical findings, which pose significant risk to the organization."
        elif severity_counts['high'] > 0:
            summary += "High-priority remediation is recommended for the identified high-severity issues."
        else:
            summary += "The overall security posture is reasonable, with opportunities for improvement in the identified areas."
        
        return summary
    
    def register_custom_generator(self, format_type: ReportFormat, 
                                 generator: Callable):
        """Register a custom report generator"""
        self.custom_generators[format_type] = generator
    
    def export_to_file(self, report_content: str, output_path: str,
                      format_type: ReportFormat):
        """Export report to file"""
        mode = 'w'
        encoding = 'utf-8'
        
        with open(output_path, mode, encoding=encoding) as f:
            f.write(report_content)
        
        return output_path
