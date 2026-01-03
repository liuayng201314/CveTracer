#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CveTracer MCP Server

将CveTracer的功能封装为MCP工具，为AI助手提供漏洞查询和Maven项目依赖分析能力。

使用 FastMCP 框架构建，提供简洁的工具定义方式。

主要功能：
- 查询CVE漏洞详细信息
- 分析Maven项目pom.xml文件中的漏洞
- 生成AI分析提示词供客户端大模型使用
"""

import json
import os
import logging
import sys
from typing import Optional

# 在导入 FastMCP 之前禁用所有第三方库的日志输出
# 禁用 FastMCP 和 MCP 相关的日志输出
logging.getLogger('fastmcp').setLevel(logging.CRITICAL)
logging.getLogger('mcp').setLevel(logging.CRITICAL)
logging.getLogger('server').setLevel(logging.CRITICAL)
logging.getLogger('cyclopts').setLevel(logging.CRITICAL)

# 设置环境变量禁用日志
os.environ.setdefault('FASTMCP_LOG_LEVEL', 'CRITICAL')
os.environ.setdefault('MCP_LOG_LEVEL', 'CRITICAL')

from fastmcp import FastMCP

from infrastructure.logging_config import setup_logging, get_logger
from core.vulnerability.query_api import VulnQueryAPI

# 设置日志（只保留文件日志，不输出到控制台）
setup_logging()
logger = get_logger(__name__)

# 创建 FastMCP 服务器实例
mcp = FastMCP("CveTracer")

# 全局变量存储漏洞查询API实例（单例模式）
vuln_api_cache: Optional[VulnQueryAPI] = None


def get_vuln_api() -> VulnQueryAPI:
    """
    获取或创建漏洞查询API实例（单例模式，带缓存）
    
    从环境变量中获取代理配置，如果已存在实例则复用。
    
    Returns:
        VulnQueryAPI: 漏洞查询API实例
    """
    global vuln_api_cache

    if vuln_api_cache is None:
        logger.info("创建新的漏洞查询API实例")
        
        # 从环境变量获取代理配置
        proxy_host = os.getenv("PROXY_HOST")
        proxy_port_str = os.getenv("PROXY_PORT")
        proxy_username = os.getenv("PROXY_USERNAME")
        proxy_password = os.getenv("PROXY_PASSWORD")

        # 转换端口号为整数
        proxy_port: Optional[int] = None
        if proxy_port_str:
            try:
                proxy_port = int(proxy_port_str)
            except ValueError:
                logger.warning(f"无效的代理端口号: {proxy_port_str}，将忽略代理端口配置")
                proxy_port = None

        vuln_api_cache = VulnQueryAPI(
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            proxy_username=proxy_username,
            proxy_password=proxy_password
        )
        logger.info("漏洞查询API实例创建成功")
    else:
        logger.debug("复用现有漏洞查询API实例")

    return vuln_api_cache


@mcp.tool()
def query_vulnerability_info(vuln_id: str) -> str:
    """
    查询漏洞详细信息，支持CVE编号查询。
    
    Args:
        vuln_id: 漏洞ID，支持CVE-xxx格式，例如 "CVE-2021-44228"
    
    Returns:
        JSON格式的漏洞信息，包含漏洞详情、CVSS评分、CWE分类等
    """
    logger.info(f"开始查询漏洞信息: {vuln_id}")
    
    try:
        vuln_api = get_vuln_api()
        logger.info("获取漏洞查询API实例成功")

        logger.info(f"调用漏洞查询API，查询ID: {vuln_id}")
        result = vuln_api.query_cve(vuln_id)
        logger.info(f"漏洞查询API返回结果: success={result.get('success', False)}")
        
        if result["success"]:
            # 提取关键信息用于大模型分析
            formatted_info = result.get("formatted_info", "")

            # 构建用于大模型分析的摘要信息
            summary = {
                "vuln_id": vuln_id,
                "success": True,
                "formatted_info": formatted_info,
                "note": "请基于以上信息进行漏洞分析和总结，重点关注严重程度、影响范围和修复建议"
            }
        else:
            summary = {
                "vuln_id": vuln_id,
                "success": False,
                "error": result.get("error", "Unknown error"),
                "note": "查询失败，请检查漏洞ID格式或网络连接"
            }

        return json.dumps(summary, indent=2, ensure_ascii=False)

    except Exception as e:
        logger.error(f"漏洞查询异常: {str(e)}", exc_info=True)
        return json.dumps({
            "vuln_id": vuln_id,
            "success": False,
            "error": f"查询异常: {str(e)}"
        }, indent=2, ensure_ascii=False)


@mcp.tool()
def analyze_pom_vulnerabilities(
    pom_path: str,
    vulnerability_ids: list[str],
    project_path: Optional[str] = None
) -> str:
    """
    深度分析Maven项目的pom.xml文件，针对指定漏洞ID进行安全评估。
    
    功能包括：
    1. 解析项目依赖关系树
    2. 查询漏洞详细信息（支持CVE）
    3. 生成分析提示词供客户端大模型使用
    4. 返回项目信息、依赖关系和漏洞详情
    
    客户端可使用返回的提示词进行AI分析生成修复方案、升级步骤、风险评估、安全建议和测试策略。
    
    Args:
        pom_path: pom.xml文件的路径，支持绝对路径或相对于project_path的相对路径
        vulnerability_ids: 要分析的漏洞ID列表，支持CVE格式，例如 ["CVE-2021-44228", "CVE-2021-45046"]
        project_path: Java项目的根目录路径（可选），当pom_path为相对路径时用于路径拼接，也可用于提供项目上下文信息
    
    Returns:
        JSON格式的分析结果，包含项目信息、依赖列表、漏洞详情和AI分析提示词
    """
    logger.info(f"开始分析POM漏洞 - POM路径: {pom_path}")
    if project_path:
        logger.info(f"项目路径: {project_path}")
    logger.info(f"指定漏洞ID: {vulnerability_ids}")
    
    # 验证漏洞ID列表不为空
    if not vulnerability_ids or len(vulnerability_ids) == 0:
        logger.error("漏洞ID列表为空")
        return json.dumps({
            "success": False,
            "error": "漏洞ID列表不能为空，必须指定要分析的漏洞ID",
            "pom_path": pom_path,
            "note": "请提供有效的漏洞ID列表，如['CVE-2021-44228', 'CVE-2021-45046']"
        }, indent=2, ensure_ascii=False)
    
    try:
        vuln_api = get_vuln_api()
        logger.info("获取漏洞查询API实例成功")
        
        # 调用POM漏洞分析函数
        logger.info("开始执行POM漏洞分析")
        from core.parser.pom_parser import analyze_pom_vulnerabilities as analyze_pom
        result = analyze_pom(
            pom_path=pom_path,
            vulnerability_ids=vulnerability_ids,
            project_path=project_path,
            vuln_api=vuln_api
        )
        
        logger.info(f"POM漏洞分析完成，成功: {result.get('success', False)}")
        
        return json.dumps(result, indent=2, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"POM漏洞分析异常: {str(e)}", exc_info=True)
        return json.dumps({
            "success": False,
            "error": f"分析异常: {str(e)}",
            "pom_path": pom_path
        }, indent=2, ensure_ascii=False)


def main() -> None:
    """主函数：启动 MCP 服务器"""
    logger.info("启动CveTracer MCP服务器...")
    mcp.run()


if __name__ == "__main__":
    main()
