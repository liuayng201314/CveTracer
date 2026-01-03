#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POM 文件解析和漏洞分析模块

提供 Maven 项目依赖分析和漏洞修复建议功能。

主要功能：
- 解析 pom.xml 文件，提取项目信息和依赖列表
- 查询漏洞详细信息
- 生成 AI 分析提示词供客户端大模型使用

示例：
    >>> from core.parser.pom_parser import analyze_pom_vulnerabilities
    >>> result = analyze_pom_vulnerabilities(
    ...     pom_path="pom.xml",
    ...     vulnerability_ids=["CVE-2021-44228"]
    ... )
    >>> print(result["analysis_prompts"]["system_prompt"])
"""

import json
import os
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from infrastructure.logging_config import get_logger
from core.vulnerability.query_api import VulnQueryAPI

# 设置日志
logger = get_logger(__name__)


@dataclass
class Dependency:
    """依赖项数据类"""
    group_id: str
    artifact_id: str
    version: str
    scope: str = "compile"
    type: str = "jar"
    classifier: Optional[str] = None
    
    def to_coordinate(self) -> str:
        """转换为Maven坐标格式"""
        coord = f"{self.group_id}:{self.artifact_id}"
        if self.classifier:
            coord += f":{self.classifier}"
        coord += f":{self.version}"
        return coord
    
    def to_dict(self) -> Dict[str, str]:
        """转换为字典格式"""
        return {
            "group_id": self.group_id,
            "artifact_id": self.artifact_id,
            "version": self.version,
            "scope": self.scope,
            "type": self.type,
            "classifier": self.classifier,
            "coordinate": self.to_coordinate()
        }


class PomXmlParser:
    """POM文件解析器"""
    
    def __init__(self, pom_path: str):
        """
        初始化POM解析器
        
        Args:
            pom_path: POM文件路径
        """
        self.pom_path = pom_path
        self.tree = None
        self.root = None
        self.project_info = {}
        self.dependencies = []
        self.properties = {}
        
    def parse(self) -> bool:
        """
        解析POM文件
        
        Returns:
            解析是否成功
        """
        try:
            if not os.path.exists(self.pom_path):
                logger.error(f"POM文件不存在: {self.pom_path}")
                return False
                
            logger.info(f"开始解析POM文件: {self.pom_path}")
            self.tree = ET.parse(self.pom_path)
            self.root = self.tree.getroot()
            
            # 解析项目基本信息
            self._parse_project_info()
            
            # 解析属性
            self._parse_properties()
            
            # 解析依赖
            self._parse_dependencies()
            
            logger.info(f"POM解析完成，找到 {len(self.dependencies)} 个依赖")
            return True
            
        except ET.ParseError as e:
            logger.error(f"POM文件解析失败: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"POM解析异常: {str(e)}", exc_info=True)
            return False
    
    def _parse_project_info(self):
        """解析项目基本信息"""
        try:
            # 处理命名空间
            ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
            
            # 获取项目基本信息
            self.project_info = {
                "group_id": self._get_text_by_path("groupId", ns),
                "artifact_id": self._get_text_by_path("artifactId", ns),
                "version": self._get_text_by_path("version", ns),
                "packaging": self._get_text_by_path("packaging", ns) or "jar",
                "name": self._get_text_by_path("name", ns),
                "description": self._get_text_by_path("description", ns)
            }
            
            logger.info(f"项目信息: {self.project_info['group_id']}:{self.project_info['artifact_id']}:{self.project_info['version']}")
            
        except Exception as e:
            logger.error(f"解析项目信息失败: {str(e)}")
    
    def _parse_properties(self):
        """解析属性"""
        try:
            ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
            properties_elem = self.root.find("maven:properties", ns)
            
            if properties_elem is not None:
                for prop in properties_elem:
                    # 移除命名空间前缀
                    tag_name = prop.tag.split('}')[-1] if '}' in prop.tag else prop.tag
                    self.properties[tag_name] = prop.text or ""
                    
            logger.info(f"解析到 {len(self.properties)} 个属性")
            
        except Exception as e:
            logger.error(f"解析属性失败: {str(e)}")
    
    def _parse_dependencies(self):
        """解析依赖"""
        try:
            ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
            dependencies_elem = self.root.find("maven:dependencies", ns)
            
            if dependencies_elem is not None:
                for dep_elem in dependencies_elem.findall("maven:dependency", ns):
                    dependency = self._parse_single_dependency(dep_elem, ns)
                    if dependency:
                        self.dependencies.append(dependency)
            
            logger.info(f"解析到 {len(self.dependencies)} 个依赖")
            
        except Exception as e:
            logger.error(f"解析依赖失败: {str(e)}")
    
    def _parse_single_dependency(self, dep_elem, ns) -> Optional[Dependency]:
        """解析单个依赖"""
        try:
            group_id = self._get_text_by_element(dep_elem, "groupId", ns)
            artifact_id = self._get_text_by_element(dep_elem, "artifactId", ns)
            version = self._get_text_by_element(dep_elem, "version", ns)
            scope = self._get_text_by_element(dep_elem, "scope", ns) or "compile"
            type_elem = self._get_text_by_element(dep_elem, "type", ns) or "jar"
            classifier = self._get_text_by_element(dep_elem, "classifier", ns)
            
            # 处理版本变量替换
            if version and version.startswith("${") and version.endswith("}"):
                prop_name = version[2:-1]
                version = self.properties.get(prop_name, version)
            
            if group_id and artifact_id and version:
                return Dependency(
                    group_id=group_id,
                    artifact_id=artifact_id,
                    version=version,
                    scope=scope,
                    type=type_elem,
                    classifier=classifier
                )
            
        except Exception as e:
            logger.error(f"解析单个依赖失败: {str(e)}")
            
        return None
    
    def _get_text_by_path(self, path: str, ns: Dict[str, str]) -> Optional[str]:
        """根据路径获取文本内容"""
        try:
            elem = self.root.find(f"maven:{path}", ns)
            return elem.text if elem is not None else None
        except Exception:
            return None
    
    def _get_text_by_element(self, parent_elem, path: str, ns: Dict[str, str]) -> Optional[str]:
        """从父元素中根据路径获取文本内容"""
        try:
            elem = parent_elem.find(f"maven:{path}", ns)
            return elem.text if elem is not None else None
        except Exception:
            return None
    
    def get_dependencies_by_coordinate(self, coordinates: List[str]) -> List[Dependency]:
        """
        根据Maven坐标查找依赖
        
        Args:
            coordinates: Maven坐标列表，格式如 ["org.apache.logging.log4j:log4j-core"]
            
        Returns:
            匹配的依赖列表
        """
        matched_deps = []
        
        for coord in coordinates:
            # 解析坐标
            parts = coord.split(":")
            if len(parts) >= 2:
                group_id = parts[0]
                artifact_id = parts[1]
                
                # 查找匹配的依赖
                for dep in self.dependencies:
                    if dep.group_id == group_id and dep.artifact_id == artifact_id:
                        matched_deps.append(dep)
                        break
        
        return matched_deps
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "project_info": self.project_info,
            "properties": self.properties,
            "dependencies": [dep.to_dict() for dep in self.dependencies],
            "total_dependencies": len(self.dependencies)
        }


def analyze_pom_vulnerabilities(
    pom_path: str,
    vulnerability_ids: List[str],
    project_path: Optional[str] = None,
    vuln_api: Optional[VulnQueryAPI] = None
) -> Dict[str, Any]:
    """
    分析POM文件中的漏洞并提供修复建议
    
    Args:
        pom_path: POM文件路径
        vulnerability_ids: 漏洞ID列表
        project_path: 项目路径（可选）
        vuln_api: 漏洞查询API实例（可选）
        
    Returns:
        分析结果字典
    """
    logger.info(f"开始分析POM漏洞 - POM路径: {pom_path}, 漏洞ID: {vulnerability_ids}")
    
    try:
        # 检查POM文件是否存在，如果不存在且提供了project_path，尝试拼接路径
        actual_pom_path = pom_path
        if not os.path.exists(pom_path) and project_path:
            # 尝试拼接project_path和pom_path
            if os.path.isabs(pom_path):
                # 如果pom_path是绝对路径，直接使用
                actual_pom_path = pom_path
            else:
                # 如果pom_path是相对路径，与project_path拼接
                actual_pom_path = os.path.join(project_path, pom_path)
                logger.info(f"POM文件不存在，尝试拼接路径: {actual_pom_path}")
        
        # 再次检查文件是否存在
        if not os.path.exists(actual_pom_path):
            return {
                "success": False,
                "error": f"POM文件不存在: {actual_pom_path}",
                "pom_path": pom_path,
                "actual_pom_path": actual_pom_path,
                "project_path": project_path
            }
        
        # 解析POM文件
        parser = PomXmlParser(actual_pom_path)
        if not parser.parse():
            return {
                "success": False,
                "error": "POM文件解析失败",
                "pom_path": actual_pom_path
            }
        
        # 获取漏洞查询API
        if vuln_api is None:
            from core.vulnerability.query_api import VulnQueryAPI
            vuln_api = VulnQueryAPI()
        
        # 查询漏洞详细信息
        vuln_details = []
        for vuln_id in vulnerability_ids:
            logger.info(f"查询漏洞信息: {vuln_id}")
            vuln_result = vuln_api.query_cve(vuln_id)
            
            if vuln_result.get("success", False):
                # 提取关键信息
                vuln_data = vuln_result.get("data", {})
                cvss3 = vuln_data.get("cvss3", {})
                
                vuln_details.append({
                    "vuln_id": vuln_id,
                    "formatted_info": vuln_result.get("formatted_info", ""),
                    "severity": cvss3.get("severity", vuln_data.get("severity", "UNKNOWN")),
                    "cvss_score": cvss3.get("baseScore", vuln_data.get("overallScore", "N/A")),
                    "source": vuln_result.get("source", "CVE API")
                })
            else:
                logger.warning(f"漏洞查询失败: {vuln_id}")
                vuln_details.append({
                    "vuln_id": vuln_id,
                    "formatted_info": f"查询失败: {vuln_result.get('error', 'Unknown error')}",
                    "severity": "UNKNOWN",
                    "cvss_score": "N/A",
                    "source": vuln_result.get("source", "CVE API"),
                    "error": vuln_result.get("error", "Unknown error")
                })
        
        # 生成分析提示词（供客户端大模型使用）
        analysis_prompts = generate_vulnerability_analysis_prompts(
            parser, vuln_details, project_path
        )
        
        return {
            "success": True,
            "pom_path": pom_path,
            "project_info": parser.project_info,
            "total_dependencies": len(parser.dependencies),
            "vulnerability_analysis": vuln_details,
            "dependencies": [dep.to_dict() for dep in parser.dependencies],
            "analysis_prompts": analysis_prompts,
            "usage_guide": {
                "description": "使用返回的提示词调用客户端大模型进行漏洞分析和修复方案生成",
                "steps": [
                    "1. 从返回结果的 analysis_prompts.system_prompt 获取系统提示词",
                    "2. 从返回结果的 analysis_prompts.user_prompt 获取用户提示词",
                    "3. 使用这两个提示词调用客户端大模型API（如OpenAI、Claude等）",
                    "4. 大模型将返回结构化的JSON格式漏洞分析和修复方案"
                ],
                "example_code": {
                    "python_openai": "import openai\n\nresult = analyze_pom_vulnerabilities(...)\nprompts = result['analysis_prompts']\n\nmessages = [\n    {'role': 'system', 'content': prompts['system_prompt']},\n    {'role': 'user', 'content': prompts['user_prompt']}\n]\n\nresponse = openai.ChatCompletion.create(\n    model='gpt-4',\n    messages=messages\n)\nanalysis_result = response.choices[0].message.content",
                    "note": "返回的analysis_result应该是JSON格式，包含漏洞摘要、受影响依赖、修复方案等结构化信息"
                }
            }
        }
        
    except Exception as e:
        logger.error(f"POM漏洞分析异常: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": f"分析异常: {str(e)}",
            "pom_path": pom_path
        }


def generate_vulnerability_analysis_prompts(
    parser: PomXmlParser,
    vuln_details: List[Dict[str, Any]],
    project_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    生成漏洞分析提示词（供客户端大模型使用）
    
    Args:
        parser: POM解析器实例
        vuln_details: 漏洞详细信息列表
        project_path: 项目路径
        
    Returns:
        包含system_prompt和user_prompt的字典
    """
    try:
        # 构建系统提示词
        system_prompt = """你是一个专业的Java安全专家和Maven依赖管理专家。你的任务是分析Maven项目中的安全漏洞，并提供详细的修复方案。

## 分析要求
1. **漏洞影响评估**: 分析每个漏洞对项目的具体影响
2. **依赖关系分析**: 识别受影响的依赖及其在项目中的作用
3. **修复方案制定**: 提供具体的升级步骤和安全建议
4. **风险评估**: 评估修复过程中的潜在风险
5. **实施指导**: 提供可执行的修复步骤

## 输出格式
请按照以下JSON格式输出分析结果：
```json
{
  "vulnerability_summary": {
    "total_vulnerabilities": 数量,
    "critical_count": 严重漏洞数量,
    "high_count": 高危漏洞数量,
    "medium_count": 中危漏洞数量,
    "low_count": 低危漏洞数量
  },
  "affected_dependencies": [
    {
      "coordinate": "group:artifact:version",
      "vulnerability_ids": ["CVE-xxx"],
      "current_version": "当前版本",
      "recommended_version": "推荐版本",
      "impact_level": "严重程度",
      "description": "漏洞描述"
    }
  ],
  "fix_plan": {
    "immediate_actions": [
      {
        "action": "具体操作",
        "description": "操作描述",
        "risk_level": "风险等级",
        "estimated_time": "预估时间"
      }
    ],
    "upgrade_steps": [
      {
        "step": 1,
        "description": "步骤描述",
        "commands": ["具体命令"],
        "verification": "验证方法"
      }
    ],
    "security_recommendations": [
      {
        "category": "建议类别",
        "recommendation": "具体建议",
        "priority": "优先级"
      }
    ]
  },
  "testing_strategy": {
    "unit_tests": "单元测试建议",
    "integration_tests": "集成测试建议",
    "security_tests": "安全测试建议"
  },
  "rollback_plan": {
    "backup_strategy": "备份策略",
    "rollback_steps": ["回滚步骤"],
    "verification": "回滚验证"
  }
}
```"""

        # 构建用户提示词
        user_prompt = f"""## POM文件信息
**项目信息:**
- Group ID: {parser.project_info.get('group_id', 'N/A')}
- Artifact ID: {parser.project_info.get('artifact_id', 'N/A')}
- Version: {parser.project_info.get('version', 'N/A')}
- Packaging: {parser.project_info.get('packaging', 'jar')}

**项目路径:** {project_path or 'N/A'}

**依赖总数:** {len(parser.dependencies)}

**主要依赖（前10个，共{len(parser.dependencies)}个）:**
{json.dumps([dep.to_dict() for dep in parser.dependencies[:10]], indent=2, ensure_ascii=False)}

**注意：** 完整的依赖列表已包含在返回结果的 dependencies 字段中，请参考完整列表进行依赖匹配分析。

## 漏洞详细信息
{json.dumps(vuln_details, indent=2, ensure_ascii=False)}

## 分析要求
请基于以上信息，分析项目中的安全漏洞，并提供详细的修复方案。重点关注：
1. 受影响的依赖项识别
2. 版本升级建议
3. 具体的修复步骤
4. 安全配置建议
5. 测试和验证方案
6. 回滚计划

请提供可执行的、详细的修复指导。"""

        logger.info("生成漏洞分析提示词完成")
        return {
            "system_prompt": system_prompt.strip(),
            "user_prompt": user_prompt.strip(),
            "description": "这两个提示词用于调用客户端大模型进行漏洞分析和修复方案生成",
            "expected_output_format": "JSON格式的漏洞分析结果，包含漏洞摘要、受影响依赖、修复方案、测试策略和回滚计划"
        }
            
    except Exception as e:
        logger.error(f"生成分析提示词异常: {str(e)}", exc_info=True)
        return {
            "error": f"生成分析提示词异常: {str(e)}",
            "note": "提示词生成失败"
        }


# 使用示例
if __name__ == "__main__":
    # 测试POM解析
    pom_path = "tests/test_pom.xml"
    vulnerability_ids = ["CVE-2021-44228", "CVE-2021-45046"]
    
    result = analyze_pom_vulnerabilities(pom_path, vulnerability_ids)
    print(json.dumps(result, indent=2, ensure_ascii=False))
