# 开源依赖供应链风险画像分析工具

基于NVD漏洞数据库的开源软件供应链安全风险分析与可视化工具。

## 项目简介

本项目通过分析CVE漏洞数据和CPE软件标识信息，构建开源依赖的风险画像，帮助开发者识别和评估软件供应链中的安全风险。

## 功能特性

- CVE漏洞数据解析与统计分析
- 软件组件风险评分计算
- 漏洞趋势分析与可视化
- 供应链依赖风险画像生成

## 数据来源

- NVD (National Vulnerability Database) CVE漏洞数据
- CPE (Common Platform Enumeration) 软件标识数据

## 项目结构

```
├── src/
│   ├── data_loader.py      # 数据加载模块
│   ├── risk_analyzer.py    # 风险分析模块
│   ├── visualizer.py       # 可视化模块
│   └── report_generator.py # 报告生成模块
├── data/                   # 数据文件目录
├── docs/                   # 文档目录
└── output/                 # 输出结果目录
```

## 使用方法

```bash
# 安装依赖
pip install -r requirements.txt

# 运行分析
python src/main.py --data ./data
```

## 依赖环境

- Python 3.8+
- pandas
- matplotlib
- seaborn

## 许可证

MIT License
