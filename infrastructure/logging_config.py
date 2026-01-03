import os
import sys
from pathlib import Path
from typing import Optional

from loguru import logger


def setup_logging(config_path: Optional[str] = None) -> None:
    """
    设置日志配置
    
    Args:
        config_path: 配置文件路径，如果为None则使用默认配置
    """
    # 默认配置
    default_config = {
        'console_level': 'INFO',
        'file_level': 'INFO',
        'rotation': '1 day',
        'retention': '1 week',
        'compression': 'zip',
        'max_file_size': '10 MB'
    }

    log_config = default_config.copy()

    # 尝试读取配置文件
    if config_path and Path(config_path).exists():
        try:
            import yaml
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            log_config.update(config.get('logging', {}))
        except Exception as e:
            # 使用 stderr 输出警告，避免干扰 MCP 的 stdout JSON 通信
            print(f"Warning: Could not load logging config from {config_path}: {e}", file=sys.stderr)
            print("Using default logging configuration", file=sys.stderr)
    else:
        # 使用环境变量覆盖默认配置
        log_config.update({
            'console_level': os.getenv('LOG_CONSOLE_LEVEL', default_config['console_level']),
            'file_level': os.getenv('LOG_FILE_LEVEL', default_config['file_level']),
            'rotation': os.getenv('LOG_ROTATION', default_config['rotation']),
            'retention': os.getenv('LOG_RETENTION', default_config['retention']),
            'compression': os.getenv('LOG_COMPRESSION', default_config['compression']),
            'max_file_size': os.getenv('LOG_MAX_FILE_SIZE', default_config['max_file_size'])
        })

    # 确保日志目录存在 - 使用用户主目录下的 .cvetracer/logs
    log_dir = Path.home() / ".cvetracer" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    # 移除默认处理器
    logger.remove()

    # 完全禁用控制台日志输出，只保留文件日志
    # 这样可以避免干扰 MCP 的 stdout JSON 通信

    # 添加文件处理器 - 所有级别
    logger.add(
        log_dir / "app.log",
        rotation=log_config.get('rotation', '1 day'),
        retention=log_config.get('retention', '1 week'),
        compression=log_config.get('compression', 'zip'),
        level=log_config.get('file_level', 'INFO'),
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} - {message}",
        enqueue=True,  # 异步写入，提高性能
        backtrace=True,  # 包含堆栈跟踪
        diagnose=True,  # 包含变量值
        encoding='utf-8'
    )

    # 添加文件处理器 - ERROR级别
    logger.add(
        log_dir / "error.log",
        rotation=log_config.get('rotation', '1 day'),
        retention=log_config.get('retention', '1 week'),
        compression=log_config.get('compression', 'zip'),
        level="ERROR",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} - {message}",
        enqueue=True,
        backtrace=True,
        diagnose=True,
        encoding='utf-8'
    )

    # 添加文件处理器 - 访问日志
    logger.add(
        log_dir / "access.log",
        rotation=log_config.get('rotation', '1 day'),
        retention=log_config.get('retention', '1 week'),
        compression=log_config.get('compression', 'zip'),
        level="INFO",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | ACCESS | {message}",
        filter=lambda record: record["extra"].get("access_log", False),
        enqueue=True,
        encoding='utf-8'
    )


def get_logger(name: str = None):
    """获取logger实例"""
    return logger.bind(name=name)


def get_log_file_paths() -> dict:
    """
    获取所有日志文件的路径
    
    Returns:
        dict: 包含各种日志文件路径的字典
    """
    log_dir = Path.home() / ".cvetracer" / "logs"
    return {
        'app_log': str(log_dir / 'app.log'),
        'error_log': str(log_dir / 'error.log'),
        'access_log': str(log_dir / 'access.log'),
        'log_directory': str(log_dir)
    }


def ensure_log_directory():
    """确保日志目录存在"""
    log_dir = Path.home() / ".cvetracer" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return str(log_dir)
