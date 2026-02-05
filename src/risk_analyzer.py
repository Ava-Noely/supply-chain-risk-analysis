"""
风险分析模块
实现供应链风险评估算法
"""
import pandas as pd
import numpy as np
from typing import Dict, List, Optional
from collections import defaultdict


class RiskAnalyzer:
    """供应链风险分析器"""

    SEVERITY_WEIGHTS = {
        'CRITICAL': 10.0,
        'HIGH': 7.5,
        'MEDIUM': 5.0,
        'LOW': 2.5,
        'NONE': 0.0
    }

    def __init__(self, cve_data: pd.DataFrame, cpe_data: pd.DataFrame, junction_data: pd.DataFrame):
        self.cve_data = cve_data
        self.cpe_data = cpe_data
        self.junction_data = junction_data
        self._risk_scores = {}

    def calculate_vendor_risk(self) -> pd.DataFrame:
        """计算厂商风险评分"""
        merged = self.junction_data.merge(self.cve_data, on='cveId', how='left')
        merged = merged.merge(self.cpe_data[['cpe23Uri', 'vendor', 'product']], on='cpe23Uri', how='left')

        vendor_stats = merged.groupby('vendor').agg({
            'cveId': 'count',
            'baseScore': ['mean', 'max', 'sum'],
            'baseSeverity': lambda x: (x == 'CRITICAL').sum()
        }).reset_index()

        vendor_stats.columns = ['vendor', 'cve_count', 'avg_score', 'max_score', 'total_score', 'critical_count']

        vendor_stats['risk_score'] = (
            vendor_stats['cve_count'] * 0.3 +
            vendor_stats['avg_score'] * 0.25 +
            vendor_stats['max_score'] * 0.15 +
            vendor_stats['critical_count'] * 0.3
        )

        vendor_stats['risk_level'] = pd.cut(
            vendor_stats['risk_score'],
            bins=[0, 5, 15, 30, float('inf')],
            labels=['低风险', '中风险', '高风险', '极高风险']
        )

        return vendor_stats.sort_values('risk_score', ascending=False)

    def calculate_product_risk(self, top_n: int = 50) -> pd.DataFrame:
        """计算产品风险评分"""
        merged = self.junction_data.merge(self.cve_data, on='cveId', how='left')
        merged = merged.merge(self.cpe_data[['cpe23Uri', 'vendor', 'product']], on='cpe23Uri', how='left')

        product_stats = merged.groupby(['vendor', 'product']).agg({
            'cveId': 'count',
            'baseScore': ['mean', 'max'],
            'baseSeverity': lambda x: (x == 'CRITICAL').sum()
        }).reset_index()

        product_stats.columns = ['vendor', 'product', 'cve_count', 'avg_score', 'max_score', 'critical_count']

        product_stats['risk_score'] = (
            product_stats['cve_count'] * 0.35 +
            product_stats['avg_score'] * 0.25 +
            product_stats['max_score'] * 0.15 +
            product_stats['critical_count'] * 0.25
        )

        return product_stats.nlargest(top_n, 'risk_score')

    def analyze_severity_distribution(self) -> Dict[str, int]:
        """分析漏洞严重程度分布"""
        if 'baseSeverity' not in self.cve_data.columns:
            return {}
        return self.cve_data['baseSeverity'].value_counts().to_dict()

    def analyze_yearly_trend(self) -> pd.DataFrame:
        """分析漏洞年度趋势"""
        if 'year' not in self.cve_data.columns:
            return pd.DataFrame()

        yearly = self.cve_data.groupby('year').agg({
            'cveId': 'count',
            'baseScore': 'mean'
        }).reset_index()

        yearly.columns = ['year', 'cve_count', 'avg_severity']
        return yearly.sort_values('year')

    def identify_high_risk_components(self, threshold: float = 8.0) -> List[Dict]:
        """识别高风险组件"""
        cpe_cols = ['cpe23Uri', 'vendor', 'product']
        if 'version' in self.cpe_data.columns:
            cpe_cols.append('version')
        merged = self.junction_data.merge(self.cve_data, on='cveId', how='left')
        merged = merged.merge(self.cpe_data[cpe_cols], on='cpe23Uri', how='left')

        high_risk = merged[merged['baseScore'] >= threshold].head(500)

        components = []
        for _, row in high_risk.iterrows():
            components.append({
                'vendor': row.get('vendor', 'unknown'),
                'product': row.get('product', 'unknown'),
                'version': row.get('version', '*') if 'version' in row else '*',
                'cve_id': row['cveId'],
                'score': row['baseScore'],
                'severity': row.get('baseSeverity', 'UNKNOWN')
            })

        return components

    def generate_risk_profile(self) -> Dict:
        """生成完整风险画像"""
        profile = {
            'summary': {
                'total_cves': len(self.cve_data),
                'total_cpes': len(self.cpe_data),
                'severity_distribution': self.analyze_severity_distribution()
            },
            'yearly_trend': self.analyze_yearly_trend().to_dict('records'),
            'top_risk_vendors': self.calculate_vendor_risk().head(20).to_dict('records'),
            'top_risk_products': self.calculate_product_risk(30).to_dict('records'),
            'critical_components': self.identify_high_risk_components(9.0)[:50]
        }
        return profile
