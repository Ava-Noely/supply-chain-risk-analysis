"""
报告生成模块
生成风险分析报告
"""
import json
import os
from datetime import datetime
from typing import Dict, List


class ReportGenerator:
    """风险报告生成器"""

    def __init__(self, output_dir: str = './output'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_summary_report(self, risk_profile: Dict) -> str:
        """生成摘要报告"""
        report_lines = []
        report_lines.append("=" * 60)
        report_lines.append("开源依赖供应链风险分析报告")
        report_lines.append("=" * 60)
        report_lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")

        if 'summary' in risk_profile:
            summary = risk_profile['summary']
            report_lines.append("【数据概览】")
            report_lines.append(f"  - 漏洞总数: {summary.get('total_cves', 'N/A')}")
            report_lines.append(f"  - 软件组件数: {summary.get('total_cpes', 'N/A')}")
            report_lines.append("")

            if 'severity_distribution' in summary:
                report_lines.append("【严重程度分布】")
                for severity, count in summary['severity_distribution'].items():
                    report_lines.append(f"  - {severity}: {count}")
                report_lines.append("")

        if 'top_risk_vendors' in risk_profile:
            report_lines.append("【高风险厂商 TOP 10】")
            for i, vendor in enumerate(risk_profile['top_risk_vendors'][:10], 1):
                report_lines.append(
                    f"  {i}. {vendor['vendor']} - 风险评分: {vendor['risk_score']:.2f}, "
                    f"CVE数量: {vendor['cve_count']}"
                )
            report_lines.append("")

        if 'top_risk_products' in risk_profile:
            report_lines.append("【高风险产品 TOP 10】")
            for i, product in enumerate(risk_profile['top_risk_products'][:10], 1):
                report_lines.append(
                    f"  {i}. {product['vendor']}/{product['product']} - "
                    f"风险评分: {product['risk_score']:.2f}"
                )
            report_lines.append("")

        if 'critical_components' in risk_profile:
            critical = risk_profile['critical_components'][:10]
            if critical:
                report_lines.append("【严重漏洞组件】")
                for comp in critical:
                    report_lines.append(
                        f"  - {comp['vendor']}/{comp['product']} ({comp['cve_id']}): "
                        f"评分 {comp['score']}"
                    )
                report_lines.append("")

        report_lines.append("=" * 60)
        report_lines.append("报告结束")
        report_lines.append("=" * 60)

        report_text = "\n".join(report_lines)

        filepath = os.path.join(self.output_dir, 'risk_report.txt')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_text)

        return report_text

    def generate_json_report(self, risk_profile: Dict) -> str:
        """生成JSON格式报告"""
        report = {
            'report_time': datetime.now().isoformat(),
            'data': risk_profile
        }

        filepath = os.path.join(self.output_dir, 'risk_report.json')
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2, default=str)

        return filepath

    def generate_markdown_report(self, risk_profile: Dict, chart_paths: List[str] = None) -> str:
        """生成Markdown格式报告"""
        lines = []
        lines.append("# 开源依赖供应链风险分析报告")
        lines.append("")
        lines.append(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        if 'summary' in risk_profile:
            summary = risk_profile['summary']
            lines.append("## 1. 数据概览")
            lines.append("")
            lines.append(f"- **漏洞总数**: {summary.get('total_cves', 'N/A')}")
            lines.append(f"- **软件组件数**: {summary.get('total_cpes', 'N/A')}")
            lines.append("")

            if 'severity_distribution' in summary:
                lines.append("### 严重程度分布")
                lines.append("")
                lines.append("| 严重程度 | 数量 |")
                lines.append("|---------|------|")
                for severity, count in summary['severity_distribution'].items():
                    lines.append(f"| {severity} | {count} |")
                lines.append("")

        if 'top_risk_vendors' in risk_profile:
            lines.append("## 2. 高风险厂商分析")
            lines.append("")
            lines.append("| 排名 | 厂商 | 风险评分 | CVE数量 | 严重漏洞数 |")
            lines.append("|------|------|----------|---------|------------|")
            for i, vendor in enumerate(risk_profile['top_risk_vendors'][:15], 1):
                lines.append(
                    f"| {i} | {vendor['vendor']} | {vendor['risk_score']:.2f} | "
                    f"{vendor['cve_count']} | {vendor.get('critical_count', 0)} |"
                )
            lines.append("")

        if 'top_risk_products' in risk_profile:
            lines.append("## 3. 高风险产品分析")
            lines.append("")
            lines.append("| 排名 | 厂商 | 产品 | 风险评分 | CVE数量 |")
            lines.append("|------|------|------|----------|---------|")
            for i, product in enumerate(risk_profile['top_risk_products'][:15], 1):
                lines.append(
                    f"| {i} | {product['vendor']} | {product['product']} | "
                    f"{product['risk_score']:.2f} | {product['cve_count']} |"
                )
            lines.append("")

        if 'yearly_trend' in risk_profile and risk_profile['yearly_trend']:
            lines.append("## 4. 年度趋势分析")
            lines.append("")
            lines.append("| 年份 | CVE数量 | 平均严重程度 |")
            lines.append("|------|---------|--------------|")
            for item in risk_profile['yearly_trend'][-10:]:
                lines.append(
                    f"| {int(item['year'])} | {item['cve_count']} | {item['avg_severity']:.2f} |"
                )
            lines.append("")

        if chart_paths:
            lines.append("## 5. 可视化图表")
            lines.append("")
            for path in chart_paths:
                filename = os.path.basename(path)
                lines.append(f"![{filename}]({filename})")
                lines.append("")

        lines.append("---")
        lines.append("*本报告由供应链风险分析工具自动生成*")

        report_text = "\n".join(lines)

        filepath = os.path.join(self.output_dir, 'risk_report.md')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_text)

        return filepath
