"""
可视化模块
生成风险分析图表
"""
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from typing import Optional
import os

plt.rcParams['font.sans-serif'] = ['Arial Unicode MS', 'SimHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False


class RiskVisualizer:
    """风险可视化生成器"""

    def __init__(self, output_dir: str = './output'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        sns.set_style("whitegrid")

    def plot_severity_distribution(self, severity_data: dict, save: bool = True) -> Optional[str]:
        """绘制漏洞严重程度分布饼图"""
        fig, ax = plt.subplots(figsize=(10, 8))

        labels = list(severity_data.keys())
        sizes = list(severity_data.values())

        colors = {
            'CRITICAL': '#d32f2f',
            'HIGH': '#f57c00',
            'MEDIUM': '#fbc02d',
            'LOW': '#388e3c',
            'NONE': '#757575'
        }
        pie_colors = [colors.get(label, '#9e9e9e') for label in labels]

        wedges, texts, autotexts = ax.pie(
            sizes, labels=labels, autopct='%1.1f%%',
            colors=pie_colors, startangle=90
        )

        ax.set_title('CVE Severity Distribution', fontsize=14, fontweight='bold')

        if save:
            filepath = os.path.join(self.output_dir, 'severity_distribution.png')
            plt.savefig(filepath, dpi=150, bbox_inches='tight')
            plt.close()
            return filepath
        return None

    def plot_yearly_trend(self, yearly_data: pd.DataFrame, save: bool = True) -> Optional[str]:
        """绘制漏洞年度趋势图"""
        fig, ax1 = plt.subplots(figsize=(14, 6))

        color1 = '#1976d2'
        ax1.bar(yearly_data['year'], yearly_data['cve_count'], color=color1, alpha=0.7, label='CVE Count')
        ax1.set_xlabel('Year', fontsize=12)
        ax1.set_ylabel('CVE Count', color=color1, fontsize=12)
        ax1.tick_params(axis='y', labelcolor=color1)

        ax2 = ax1.twinx()
        color2 = '#d32f2f'
        ax2.plot(yearly_data['year'], yearly_data['avg_severity'], color=color2,
                 marker='o', linewidth=2, label='Avg Severity')
        ax2.set_ylabel('Average Severity Score', color=color2, fontsize=12)
        ax2.tick_params(axis='y', labelcolor=color2)

        plt.title('CVE Yearly Trend Analysis', fontsize=14, fontweight='bold')
        fig.tight_layout()

        if save:
            filepath = os.path.join(self.output_dir, 'yearly_trend.png')
            plt.savefig(filepath, dpi=150, bbox_inches='tight')
            plt.close()
            return filepath
        return None

    def plot_top_vendors_risk(self, vendor_data: pd.DataFrame, top_n: int = 15, save: bool = True) -> Optional[str]:
        """绘制高风险厂商排行"""
        fig, ax = plt.subplots(figsize=(12, 8))

        data = vendor_data.head(top_n).sort_values('risk_score')

        colors = plt.cm.RdYlGn_r(np.linspace(0.2, 0.8, len(data)))

        bars = ax.barh(data['vendor'], data['risk_score'], color=colors)

        ax.set_xlabel('Risk Score', fontsize=12)
        ax.set_ylabel('Vendor', fontsize=12)
        ax.set_title('Top Risk Vendors in Supply Chain', fontsize=14, fontweight='bold')

        for bar, score in zip(bars, data['risk_score']):
            ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height()/2,
                    f'{score:.1f}', va='center', fontsize=9)

        plt.tight_layout()

        if save:
            filepath = os.path.join(self.output_dir, 'top_vendors_risk.png')
            plt.savefig(filepath, dpi=150, bbox_inches='tight')
            plt.close()
            return filepath
        return None

    def plot_product_heatmap(self, product_data: pd.DataFrame, save: bool = True) -> Optional[str]:
        """绘制产品风险热力图"""
        fig, ax = plt.subplots(figsize=(14, 10))

        top_products = product_data.head(20)

        pivot_data = top_products.pivot_table(
            values='risk_score',
            index='product',
            columns='vendor',
            aggfunc='first',
            fill_value=0
        )

        sns.heatmap(pivot_data, annot=True, fmt='.1f', cmap='YlOrRd',
                    ax=ax, cbar_kws={'label': 'Risk Score'})

        ax.set_title('Product Risk Heatmap', fontsize=14, fontweight='bold')
        plt.tight_layout()

        if save:
            filepath = os.path.join(self.output_dir, 'product_heatmap.png')
            plt.savefig(filepath, dpi=150, bbox_inches='tight')
            plt.close()
            return filepath
        return None

    def plot_severity_by_vendor(self, merged_data: pd.DataFrame, top_n: int = 10, save: bool = True) -> Optional[str]:
        """绘制厂商漏洞严重程度堆叠图"""
        fig, ax = plt.subplots(figsize=(14, 8))

        top_vendors = merged_data['vendor'].value_counts().head(top_n).index.tolist()
        filtered = merged_data[merged_data['vendor'].isin(top_vendors)]

        severity_counts = filtered.groupby(['vendor', 'baseSeverity']).size().unstack(fill_value=0)

        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']
        severity_counts = severity_counts.reindex(columns=[c for c in severity_order if c in severity_counts.columns])

        colors = ['#d32f2f', '#f57c00', '#fbc02d', '#388e3c', '#757575']
        severity_counts.plot(kind='bar', stacked=True, ax=ax, color=colors[:len(severity_counts.columns)])

        ax.set_xlabel('Vendor', fontsize=12)
        ax.set_ylabel('CVE Count', fontsize=12)
        ax.set_title('CVE Severity Distribution by Vendor', fontsize=14, fontweight='bold')
        ax.legend(title='Severity', bbox_to_anchor=(1.02, 1), loc='upper left')

        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()

        if save:
            filepath = os.path.join(self.output_dir, 'severity_by_vendor.png')
            plt.savefig(filepath, dpi=150, bbox_inches='tight')
            plt.close()
            return filepath
        return None

    def generate_all_charts(self, risk_profile: dict, merged_data: pd.DataFrame = None) -> list:
        """生成所有图表"""
        generated = []

        if 'summary' in risk_profile and 'severity_distribution' in risk_profile['summary']:
            path = self.plot_severity_distribution(risk_profile['summary']['severity_distribution'])
            if path:
                generated.append(path)

        if 'yearly_trend' in risk_profile:
            yearly_df = pd.DataFrame(risk_profile['yearly_trend'])
            if not yearly_df.empty:
                path = self.plot_yearly_trend(yearly_df)
                if path:
                    generated.append(path)

        if 'top_risk_vendors' in risk_profile:
            vendor_df = pd.DataFrame(risk_profile['top_risk_vendors'])
            if not vendor_df.empty:
                path = self.plot_top_vendors_risk(vendor_df)
                if path:
                    generated.append(path)

        if 'top_risk_products' in risk_profile:
            product_df = pd.DataFrame(risk_profile['top_risk_products'])
            if not product_df.empty:
                path = self.plot_product_heatmap(product_df)
                if path:
                    generated.append(path)

        return generated
