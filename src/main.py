"""
主程序入口
"""
import argparse
import os
import sys

from data_loader import DataLoader, load_all_data
from risk_analyzer import RiskAnalyzer
from visualizer import RiskVisualizer
from report_generator import ReportGenerator


def main():
    parser = argparse.ArgumentParser(description='开源依赖供应链风险画像分析工具')
    parser.add_argument('--data', type=str, default='./data', help='数据目录路径')
    parser.add_argument('--output', type=str, default='./output', help='输出目录路径')
    parser.add_argument('--cve', type=str, default='nvd_cves.csv', help='CVE数据文件名')
    parser.add_argument('--cpe', type=str, default='cpe.csv', help='CPE数据文件名')
    parser.add_argument('--junction', type=str, default='junction.csv', help='关联数据文件名')
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    print("=" * 50)
    print("开源依赖供应链风险画像分析工具")
    print("=" * 50)

    cve_path = os.path.join(args.data, args.cve)
    cpe_path = os.path.join(args.data, args.cpe)
    junction_path = os.path.join(args.data, args.junction)

    print("\n[1/4] 加载数据...")
    loader = DataLoader(args.data)

    try:
        cve_data = loader.load_cve_data(cve_path)
        print(f"  - CVE数据: {len(cve_data)} 条记录")
    except Exception as e:
        print(f"  - CVE数据加载失败: {e}")
        sys.exit(1)

    try:
        cpe_data = loader.load_cpe_data(cpe_path)
        print(f"  - CPE数据: {len(cpe_data)} 条记录")
    except Exception as e:
        print(f"  - CPE数据加载失败: {e}")
        sys.exit(1)

    try:
        junction_data = loader.load_junction_data(junction_path)
        print(f"  - 关联数据: {len(junction_data)} 条记录")
    except Exception as e:
        print(f"  - 关联数据加载失败: {e}")
        sys.exit(1)

    print("\n[2/4] 分析风险...")
    analyzer = RiskAnalyzer(cve_data, cpe_data, junction_data)
    risk_profile = analyzer.generate_risk_profile()

    print(f"  - 漏洞总数: {risk_profile['summary']['total_cves']}")
    print(f"  - 高风险厂商: {len(risk_profile['top_risk_vendors'])} 个")
    print(f"  - 高风险产品: {len(risk_profile['top_risk_products'])} 个")

    print("\n[3/4] 生成可视化...")
    visualizer = RiskVisualizer(args.output)
    merged_data = loader.get_merged_data()
    chart_paths = visualizer.generate_all_charts(risk_profile, merged_data)
    print(f"  - 生成图表: {len(chart_paths)} 个")

    print("\n[4/4] 生成报告...")
    reporter = ReportGenerator(args.output)
    reporter.generate_summary_report(risk_profile)
    reporter.generate_json_report(risk_profile)
    reporter.generate_markdown_report(risk_profile, chart_paths)
    print(f"  - 报告已保存至: {args.output}")

    print("\n" + "=" * 50)
    print("分析完成!")
    print("=" * 50)


if __name__ == '__main__':
    main()
