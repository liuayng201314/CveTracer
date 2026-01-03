"""
轻量化漏洞查询API客户端
专注于快速、简单的CVE信息获取
"""

from datetime import datetime
from typing import Dict, Any, Optional, List

import requests


class SimpleVulnAPI:
    """轻量化漏洞查询API客户端"""

    def __init__(self, proxy_host=None, proxy_port=None, proxy_username=None, proxy_password=None):
        """
        初始化API客户端
        
        Args:
            proxy_host: 代理服务器地址
            proxy_port: 代理服务器端口
            proxy_username: 代理用户名
            proxy_password: 代理密码
        """
        self.session = requests.Session()
        self.timeout = 10  # 增加到10秒超时，因为通过代理可能较慢
        self.headers = {
            'User-Agent': 'SimpleVulnAPI/1.0',
            'Accept': 'application/json'
        }
        self.session.headers.update(self.headers)

        # 配置代理
        if proxy_host and proxy_port:
            self._setup_proxy(proxy_host, proxy_port, proxy_username, proxy_password)

    def _setup_proxy(self, proxy_host, proxy_port, proxy_username=None, proxy_password=None):
        """配置代理设置"""
        proxy_url = f"http://{proxy_host}:{proxy_port}"

        # 如果有用户名和密码，添加到代理URL中
        if proxy_username and proxy_password:
            proxy_url = f"http://{proxy_username}:{proxy_password}@{proxy_host}:{proxy_port}"

        # 设置代理
        self.session.proxies = {
            'http': proxy_url,
            'https': proxy_url
        }

        print(f"[WEB] 已配置代理: {proxy_host}:{proxy_port}")
        if proxy_username:
            print(f"[AUTH] 代理认证: {proxy_username}")

    def test_connection(self):
        """测试网络连接"""
        try:
            # 测试访问NVD API
            test_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
            response = self.session.get(test_url, timeout=self.timeout)
            response.raise_for_status()
            print("[OK] 代理连接测试成功")
            return True
        except requests.exceptions.ProxyError as e:
            print(f"[ERR] 代理连接失败: {e}")
            return False
        except requests.exceptions.Timeout:
            print("[ERR] 连接超时，请检查代理设置")
            return False
        except requests.exceptions.RequestException as e:
            print(f"[ERR] 网络连接失败: {e}")
            return False

    def get_cve_info(self, cve_id: str) -> Dict[str, Any]:
        """
        获取CVE信息，返回标准化的漏洞信息结构
        
        Args:
            cve_id: CVE编号，如 'CVE-2021-44228'
            
        Returns:
            标准化的漏洞信息字典
        """
        # 1. 尝试NVD API (主要数据源)
        result = self._call_nvd_api(cve_id)
        if result and not result.get('error'):
            return result

        # 2. 尝试CVE Details API (备用数据源)
        result = self._call_cve_details_api(cve_id)
        if result and not result.get('error'):
            return result

        # 3. 返回未找到
        return {
            'name': cve_id,
            'title': cve_id,
            'description': 'CVE not found',
            'publishedDate': '',
            'source': 'none',
            'cvss3': {
                'baseScore': 0.0,
                'vector': '',
                'severity': 'UNKNOWN',
                'version': '3.1'
            },
            'overallScore': 0.0,
            'severity': 'UNKNOWN',
            'useCvss3': False,
            'cwe': [],
            '_meta': {
                'links': []
            },
            'error': 'CVE not found'
        }

    def _call_nvd_api(self, cve_id: str) -> Dict[str, Any]:
        """调用NVD API"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()
            if data.get('vulnerabilities'):
                return self._parse_nvd_response(data['vulnerabilities'][0])
            else:
                return {'error': 'CVE not found in NVD'}

        except requests.Timeout:
            return {'error': 'NVD API timeout'}
        except requests.RequestException as e:
            return {'error': f'NVD API error: {str(e)}'}
        except Exception as e:
            return {'error': f'NVD parsing error: {str(e)}'}

    def _call_cve_details_api(self, cve_id: str) -> Dict[str, Any]:
        """调用CVE Details API"""
        try:
            url = f"https://cve.circl.lu/api/cve/{cve_id}"
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()
            if data and not data.get('error'):
                return self._parse_cve_details_response(data)
            else:
                return {'error': 'CVE not found in CVE Details'}

        except requests.Timeout:
            return {'error': 'CVE Details API timeout'}
        except requests.RequestException as e:
            return {'error': f'CVE Details API error: {str(e)}'}
        except Exception as e:
            return {'error': f'CVE Details parsing error: {str(e)}'}

    def _parse_nvd_response(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """解析NVD API响应，提取标准化的漏洞信息结构"""
        cve = vuln_data.get('cve', {})
        descriptions = cve.get('descriptions', [])
        metrics = cve.get('metrics', {})
        references = cve.get('references', [])
        weaknesses = cve.get('weaknesses', [])

        # 获取描述
        description = ""
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break

        # 获取CVSS评分信息
        cvss3_score = 0.0
        cvss3_vector = ""
        cvss3_severity = "UNKNOWN"
        cvss2_score = 0.0
        cvss2_vector = ""
        cvss2_severity = "UNKNOWN"

        try:
            # 获取CVSS v3.1信息
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                for metric in metrics['cvssMetricV31']:
                    if metric.get('source') == 'nvd@nist.gov':
                        cvss_data = metric['cvssData']
                        cvss3_score = cvss_data.get('baseScore', 0.0)
                        cvss3_vector = cvss_data.get('vectorString', '')
                        cvss3_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                        break
                else:
                    # 如果没有NVD的评分，使用第一个
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    cvss3_score = cvss_data.get('baseScore', 0.0)
                    cvss3_vector = cvss_data.get('vectorString', '')
                    cvss3_severity = cvss_data.get('baseSeverity', 'UNKNOWN')

            # 获取CVSS v2信息
            if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                for metric in metrics['cvssMetricV2']:
                    if metric.get('source') == 'nvd@nist.gov':
                        cvss_data = metric['cvssData']
                        cvss2_score = cvss_data.get('baseScore', 0.0)
                        cvss2_vector = cvss_data.get('vectorString', '')
                        cvss2_severity = metric.get('baseSeverity', 'UNKNOWN')
                        break
                else:
                    cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                    cvss2_score = cvss_data.get('baseScore', 0.0)
                    cvss2_vector = cvss_data.get('vectorString', '')
                    cvss2_severity = metrics['cvssMetricV2'][0].get('baseSeverity', 'UNKNOWN')
        except (KeyError, IndexError, TypeError):
            # 如果解析失败，保持默认值
            pass

        # 提取CWE信息
        cwe_list = []
        for weakness in weaknesses:
            if 'description' in weakness:
                for desc in weakness['description']:
                    if desc.get('lang') == 'en':
                        cwe_list.append(desc.get('value', ''))

        # 提取参考链接
        reference_links = []
        for ref in references:
            if 'url' in ref:
                reference_links.append({
                    'href': ref['url'],
                    'label': 'REFERENCE',
                    'rel': 'reference'
                })

        # 提取CISA信息
        cisa_info = {}
        if 'cisaActionDue' in cve:
            cisa_info['action_due'] = cve['cisaActionDue']
        if 'cisaExploitAdd' in cve:
            cisa_info['exploit_added'] = cve['cisaExploitAdd']
        if 'cisaRequiredAction' in cve:
            cisa_info['required_action'] = cve['cisaRequiredAction']
        if 'cisaVulnerabilityName' in cve:
            cisa_info['vulnerability_name'] = cve['cisaVulnerabilityName']

        # 构建标准化的漏洞信息结构
        return {
            'name': cve.get('id', ''),
            'title': cve.get('id', ''),
            'description': description,
            'publishedDate': cve.get('published', ''),
            'lastModified': cve.get('lastModified', ''),
            'source': 'NVD',
            'cvss3': {
                'baseScore': cvss3_score,
                'vector': cvss3_vector,
                'severity': cvss3_severity,
                'version': '3.1'
            },
            'cvss2': {
                'baseScore': cvss2_score,
                'vector': cvss2_vector,
                'severity': cvss2_severity,
                'version': '2.0'
            },
            'overallScore': cvss3_score if cvss3_score > 0 else cvss2_score,
            'severity': cvss3_severity if cvss3_severity != 'UNKNOWN' else cvss2_severity,
            'useCvss3': cvss3_score > 0,
            'cwe': cwe_list,
            'cisa': cisa_info,
            '_meta': {
                'links': reference_links
            }
        }

    def _parse_cve_details_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """解析CVE Details API响应，返回标准化的漏洞信息结构"""
        cvss = data.get('cvss', 0.0)
        severity = self._map_cvss_severity(cvss)

        return {
            'name': data.get('id', ''),
            'title': data.get('id', ''),
            'description': data.get('summary', ''),
            'publishedDate': data.get('Published', ''),
            'source': 'CVE_DETAILS',
            'cvss3': {
                'baseScore': cvss,
                'vector': '',
                'severity': severity,
                'version': '3.1'
            },
            'overallScore': cvss,
            'severity': severity,
            'useCvss3': True,
            'cwe': [],
            '_meta': {
                'links': []
            }
        }

    def _map_cvss_severity(self, score: float) -> str:
        """映射CVSS评分为严重程度"""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score > 0.0:
            return 'LOW'
        else:
            return 'UNKNOWN'

    def search_vulnerabilities(self, keyword: str, severity: Optional[str] = None, limit: int = 10) -> List[
        Dict[str, Any]]:
        """
        搜索漏洞信息
        
        Args:
            keyword: 搜索关键词
            severity: 严重程度筛选
            limit: 结果数量限制
            
        Returns:
            漏洞信息列表
        """
        # 简化版搜索 - 仅返回示例数据
        # 实际实现中可以通过NVD API的搜索功能实现
        return [
            {
                'cve_id': 'CVE-2021-44228',
                'title': 'Apache Log4j2 远程代码执行漏洞',
                'description': 'Apache Log4j2 存在远程代码执行漏洞',
                'severity': 'CRITICAL',
                'cvss_score': 10.0,
                'publish_date': '2021-12-09',
                'source': 'NVD'
            }
        ]

    def format_vulnerability_info(self, vuln_data: Dict[str, Any]) -> str:
        """
        格式化漏洞信息为标准格式
        
        Args:
            vuln_data: 漏洞数据字典
            
        Returns:
            格式化后的字符串
        """
        if vuln_data.get('error'):
            return f"# 漏洞查询失败\n**错误**: {vuln_data['error']}"

        # 基本信息
        vuln_id = vuln_data.get('name', 'N/A')
        title = vuln_data.get('title', 'N/A')
        description = vuln_data.get('description', 'N/A').strip()
        published_date = vuln_data.get('publishedDate', 'N/A')
        source = vuln_data.get('source', 'N/A')

        # 评分信息
        cvss3 = vuln_data.get('cvss3', {})
        cvss3_score = cvss3.get('baseScore', 'N/A')
        cvss3_vector = cvss3.get('vector', 'N/A')
        cvss3_severity = cvss3.get('severity', 'N/A')

        # 整体评分
        overall_score = vuln_data.get('overallScore', 'N/A')

        # CWE信息
        cwe_list = vuln_data.get('cwe', [])
        vulnerability_type = ', '.join(cwe_list) if cwe_list else 'N/A'

        # CISA信息
        cisa_info = vuln_data.get('cisa', {})
        cisa_action_due = cisa_info.get('action_due', 'N/A')
        cisa_required_action = cisa_info.get('required_action', 'N/A')

        lines = [
            f"# 漏洞详细信息",
            f"**漏洞外部编号**: {vuln_id}",
            f"**漏洞名称**: {title}",
            f"**漏洞评分**: {overall_score} (CVSS3: {cvss3_score})",
            f"**评分向量**: {cvss3_vector}",
            f"**漏洞级别**: {cvss3_severity}",
            f"**漏洞类型**: {vulnerability_type}",
            f"**漏洞发现时间**: {published_date}",
            f"**数据源**: {source}",
            f"**CISA行动期限**: {cisa_action_due}",
            f"**CISA要求行动**: {cisa_required_action}",
            f"**描述**:\n{description}",
        ]

        return "\n\n".join(lines)

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'total_count': 1,
            'severity_distribution': {'CRITICAL': 1},
            'sources': {'NVD': 1},
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'running_mode': 'simple_api'
        }

    def close(self):
        """关闭会话"""
        self.session.close()
