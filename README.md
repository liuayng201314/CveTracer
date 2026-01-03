# CveTracer - Maven 项目漏洞分析工具

CveTracer 是一个专业的 Maven 项目依赖漏洞分析工具，集成了权威漏洞数据源，为 Java 项目提供全面的安全审计解决方案。通过 MCP（Model Context Protocol）协议，为 AI 助手提供漏洞查询和依赖分析能力。

## 🚀 核心功能

### 1. CVE 漏洞查询

- **多数据源整合**：集成 NVD（National Vulnerability Database）等权威漏洞库
- **CVE 查询**：支持 CVE 编号的详细漏洞信息查询
- **漏洞搜索**：支持关键词搜索和严重程度筛选
- **详细信息**：提供 CVSS 评分、CWE 分类、漏洞描述等完整信息

### 2. Maven 项目依赖分析

- **POM 文件解析**：深度解析 Maven 项目的依赖关系树
- **依赖提取**：自动提取项目所有依赖及其版本信息
- **漏洞关联**：将 CVE 漏洞与项目依赖进行关联分析
- **AI 分析提示词生成**：生成结构化的提示词供客户端大模型进行漏洞分析和修复方案生成

### 3. MCP 工具集成

- **AI 助手集成**：通过 MCP 协议为 AI 助手提供漏洞分析能力
- **自动化审计**：支持批量项目扫描和自动化报告生成
- **智能分析**：返回分析提示词，客户端可使用大模型进行智能化的漏洞分析和修复建议生成

## 📋 系统要求

- Python 3.12+
- 网络连接（用于漏洞数据查询）
- 可选：代理服务器（用于访问 NVD API）

## 🛠️ 安装配置

### 前置要求

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) - 快速的 Python 包管理器

安装 uv：

```bash
# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Linux/Mac
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 1. 克隆项目

```bash
git clone <repository-url>
cd CveTracer
```

### 2. 安装依赖

使用 uv 安装依赖（会自动创建虚拟环境）：

```bash
uv sync
```

或者使用 uv 直接运行（无需手动安装）：

```bash
uv run python mcp_server.py
```

### 4. 配置环境变量

创建`.env`文件或设置环境变量：

```bash
# 代理配置（可选，访问 NVD API 可能需要）
PROXY_HOST=your-proxy-host
PROXY_PORT=80
PROXY_USERNAME=your-username
PROXY_PASSWORD=your-password
```

> **注意**：如果不需要代理，可以跳过此步骤。某些网络环境访问 NVD API 可能需要配置代理。

### 5. MCP 配置

在 MCP 客户端配置文件中添加 CveTracer 服务器：

**使用 uv 运行（推荐）：**

```json
{
  "mcpServers": {
    "CveTracer": {
      "command": "uv",
      "args": ["run", "python", "/path/to/CveTracer/mcp_server.py"],
      "description": "Maven 项目漏洞分析工具",
      "env": {
        "PROXY_HOST": "your-proxy-host",
        "PROXY_PORT": "80",
        "PROXY_USERNAME": "your-username",
        "PROXY_PASSWORD": "your-password"
      }
    }
  }
}
```

**或使用虚拟环境中的 Python：**

```json
{
  "mcpServers": {
    "CveTracer": {
      "command": "/path/to/CveTracer/.venv/bin/python",
      "args": ["/path/to/CveTracer/mcp_server.py"],
      "description": "Maven 项目漏洞分析工具",
      "env": {
        "PROXY_HOST": "your-proxy-host",
        "PROXY_PORT": "80",
        "PROXY_USERNAME": "your-username",
        "PROXY_PASSWORD": "your-password"
      }
    }
  }
}
```

## 🔧 MCP 工具使用

通过 MCP 协议，AI 助手可以调用以下工具进行自动化安全审计：

### 可用工具

| 工具名称                      | 功能描述                                  | 主要参数                                                             |
| ----------------------------- | ----------------------------------------- | -------------------------------------------------------------------- |
| `query_vulnerability_info`    | 查询 CVE 漏洞详细信息                     | `vuln_id` (必需，CVE 编号)                                           |
| `analyze_pom_vulnerabilities` | 分析 POM 文件中的漏洞并生成 AI 分析提示词 | `pom_path` (必需), `vulnerability_ids` (必需), `project_path` (可选) |

### 使用示例

#### 1. 查询漏洞信息

```json
{
  "tool": "query_vulnerability_info",
  "parameters": {
    "vuln_id": "CVE-2021-44228"
  }
}
```

**返回结果包含：**

- 漏洞基本信息（ID、标题、描述）
- CVSS 评分和严重程度
- CWE 分类
- 发布时间和来源
- 格式化的漏洞信息

#### 2. 分析 POM 文件漏洞

```json
{
  "tool": "analyze_pom_vulnerabilities",
  "parameters": {
    "pom_path": "/path/to/pom.xml",
    "vulnerability_ids": ["CVE-2021-44228", "CVE-2021-45046"],
    "project_path": "/path/to/project"
  }
}
```

**返回结果包含：**

- 项目基本信息（Group ID、Artifact ID、Version）
- 所有依赖列表
- 漏洞详细信息
- **AI 分析提示词**（`analysis_prompts`）：
  - `system_prompt`: 系统提示词，定义 AI 分析的角色和要求
  - `user_prompt`: 用户提示词，包含项目信息和漏洞详情
  - `usage_instruction`: 使用说明和示例代码

**使用 AI 分析提示词：**

客户端可以使用返回的提示词调用大模型（如 OpenAI、Claude 等）进行漏洞分析：

```python
import openai

result = analyze_pom_vulnerabilities(...)
prompts = result['analysis_prompts']

messages = [
    {'role': 'system', 'content': prompts['system_prompt']},
    {'role': 'user', 'content': prompts['user_prompt']}
]

response = openai.ChatCompletion.create(
    model='gpt-4',
    messages=messages
)
analysis_result = response.choices[0].message.content
```

AI 将返回结构化的 JSON 格式分析结果，包含：

- 漏洞摘要统计
- 受影响的依赖项
- 修复方案和升级步骤
- 安全建议
- 测试策略
- 回滚计划

## 🎯 命令行工具

除了 MCP 接口，项目还提供了命令行工具：

使用 uv 运行（推荐）：

```bash
# 查询 CVE 漏洞
uv run python core/vulnerability/unified_query.py --cve CVE-2021-44228

# 搜索漏洞
uv run python core/vulnerability/unified_query.py --search "Apache Log4j" --limit 10

# 按严重程度搜索
uv run python core/vulnerability/unified_query.py --search "SQL" --severity HIGH

# 测试连接
uv run python core/vulnerability/unified_query.py --test-connections

# 测试代理连接
uv run python core/vulnerability/unified_query.py --test-proxy --proxy-host your-proxy --proxy-port 80

# 查看统计信息
uv run python core/vulnerability/unified_query.py --stats
```

或者激活虚拟环境后直接运行：

```bash
# 激活虚拟环境（uv sync 后）
source .venv/bin/activate  # Linux/Mac
# 或
.venv\Scripts\activate  # Windows

# 然后直接运行
python core/vulnerability/unified_query.py --cve CVE-2021-44228
```

### 命令行工具参数说明

| 参数                 | 说明              | 示例                                          |
| -------------------- | ----------------- | --------------------------------------------- |
| `--cve`              | 查询特定 CVE ID   | `--cve CVE-2021-44228`                        |
| `--search`           | 搜索关键词        | `--search "Apache"`                           |
| `--severity`         | 严重程度筛选      | `--severity HIGH`                             |
| `--limit`            | 结果数量限制      | `--limit 10`                                  |
| `--test-connections` | 测试所有 API 连接 | `--test-connections`                          |
| `--test-proxy`       | 测试代理连接      | `--test-proxy --proxy-host x --proxy-port 80` |
| `--stats`            | 显示统计信息      | `--stats`                                     |
| `--proxy-host`       | 代理服务器地址    | `--proxy-host your-proxy`                     |
| `--proxy-port`       | 代理服务器端口    | `--proxy-port 80`                             |
| `--proxy-username`   | 代理用户名        | `--proxy-username user`                       |
| `--proxy-password`   | 代理密码          | `--proxy-password pass`                       |

## 📝 开发说明

### 技术栈

- **FastMCP**: 使用 FastMCP 框架构建 MCP 服务器，提供简洁的工具定义方式
- **Python 3.12+**: 使用现代 Python 特性
- **loguru**: 日志记录框架

### 代码结构

- **core/**: 核心业务逻辑，包含解析器和漏洞查询模块
  - `parser/`: POM 文件解析器
  - `vulnerability/`: 漏洞查询模块
- **infrastructure/**: 基础设施代码，包含 API 客户端、工具函数等
  - `nvd/`: NVD API 客户端
  - `utils.py`: 工具函数
  - `logging_config.py`: 日志配置
- **mcp_server.py**: MCP 服务器主入口，使用 FastMCP 框架
- **tests/**: 测试文件目录

### 日志

项目使用 `loguru` 进行日志记录，日志文件保存在用户主目录下的 `.cvetracer/logs/` 目录：

- `~/.cvetracer/logs/app.log`: 应用日志
- `~/.cvetracer/logs/error.log`: 错误日志
- `~/.cvetracer/logs/access.log`: 访问日志

> **注意**：`~` 表示用户主目录，在 Windows 上通常是 `C:\Users\<用户名>\.cvetracer\logs\`

### 快速开始（开发模式）

使用 uv 运行 Python 脚本：

```bash
# 运行 MCP 服务器
uv run python mcp_server.py

# 运行测试脚本
uv run python -c "
from core.vulnerability.query_api import VulnQueryAPI

api = VulnQueryAPI()
result = api.query_cve('CVE-2021-44228')
print(result['formatted_info'])
"
```

或者在 Python 代码中：

```python
# 使用漏洞查询 API
from core.vulnerability.query_api import VulnQueryAPI

api = VulnQueryAPI()
result = api.query_cve("CVE-2021-44228")
print(result["formatted_info"])

# 分析 POM 文件
from core.parser.pom_parser import analyze_pom_vulnerabilities

result = analyze_pom_vulnerabilities(
    pom_path="pom.xml",
    vulnerability_ids=["CVE-2021-44228"]
)
print(result["analysis_prompts"]["system_prompt"])
```

## ❓ 常见问题

### Q: 如何配置代理？

A: 可以通过环境变量或 MCP 配置文件设置代理：

- 环境变量：`PROXY_HOST`, `PROXY_PORT`, `PROXY_USERNAME`, `PROXY_PASSWORD`
- MCP 配置：在 `mcp_config.json` 的 `env` 字段中配置

### Q: 查询漏洞时出现网络错误？

A: 请检查：

1. 网络连接是否正常
2. 是否需要配置代理（访问 NVD API 可能需要）
3. 使用 `--test-connections` 测试 API 连接

### Q: POM 文件解析失败？

A: 请确认：

1. POM 文件路径是否正确
2. POM 文件格式是否有效
3. 如果使用相对路径，是否正确设置了 `project_path`

### Q: 如何使用返回的 AI 分析提示词？

A: 返回的 `analysis_prompts` 包含 `system_prompt` 和 `user_prompt`，可以直接用于调用 OpenAI、Claude 等大模型 API。详细示例见上方"使用 AI 分析提示词"部分。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

在提交代码前，请确保：

- 代码通过 lint 检查
- 添加适当的注释和文档字符串
- 更新相关文档

## 📄 许可证

本项目采用 MIT 许可证。

---

**CveTracer** - 让 Maven 项目安全审计更简单、更智能！
