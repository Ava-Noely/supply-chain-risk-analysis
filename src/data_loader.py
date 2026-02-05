"""
数据加载模块
负责加载和预处理CVE漏洞数据
"""
import pandas as pd
from typing import Tuple, Optional


class DataLoader:
    """CVE数据加载器"""

    def __init__(self, data_dir: str = './data'):
        self.data_dir = data_dir
        self._cve_data = None
        self._cpe_data = None
        self._junction_data = None

    def load_cve_data(self, filepath: str) -> pd.DataFrame:
        """加载CVE漏洞数据"""
        df = pd.read_csv(filepath)
        df['publishedDate'] = pd.to_datetime(df['publishedDate'], errors='coerce')
        df['year'] = df['publishedDate'].dt.year
        self._cve_data = df
        return df

    def load_cpe_data(self, filepath: str) -> pd.DataFrame:
        """加载CPE软件标识数据"""
        df = pd.read_csv(filepath)
        df = self._parse_cpe_uri(df)
        self._cpe_data = df
        return df

    def load_junction_data(self, filepath: str) -> pd.DataFrame:
        """加载CVE-CPE关联数据"""
        df = pd.read_csv(filepath)
        self._junction_data = df
        return df

    def _parse_cpe_uri(self, df: pd.DataFrame) -> pd.DataFrame:
        """解析CPE URI提取软件信息"""
        if 'cpe23Uri' not in df.columns:
            return df

        parsed = df['cpe23Uri'].str.split(':', expand=True)
        if parsed.shape[1] >= 5:
            df['vendor'] = parsed[3]
            df['product'] = parsed[4]
        if parsed.shape[1] >= 6:
            df['version'] = parsed[5]
        return df

    def get_merged_data(self) -> Optional[pd.DataFrame]:
        """获取合并后的完整数据"""
        if self._cve_data is None or self._junction_data is None:
            return None

        merged = self._junction_data.merge(
            self._cve_data,
            on='cveId',
            how='left'
        )

        if self._cpe_data is not None:
            merged = merged.merge(
                self._cpe_data,
                on='cpe23Uri',
                how='left'
            )
        return merged

    def get_statistics(self) -> dict:
        """获取数据基本统计信息"""
        stats = {}
        if self._cve_data is not None:
            stats['total_cves'] = len(self._cve_data)
            stats['cve_years'] = self._cve_data['year'].value_counts().to_dict()
        if self._cpe_data is not None:
            stats['total_cpes'] = len(self._cpe_data)
            if 'vendor' in self._cpe_data.columns:
                stats['top_vendors'] = self._cpe_data['vendor'].value_counts().head(10).to_dict()
        return stats


def load_all_data(cve_path: str, cpe_path: str, junction_path: str) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """便捷函数：一次性加载所有数据"""
    loader = DataLoader()
    cve_df = loader.load_cve_data(cve_path)
    cpe_df = loader.load_cpe_data(cpe_path)
    junction_df = loader.load_junction_data(junction_path)
    return cve_df, cpe_df, junction_df
