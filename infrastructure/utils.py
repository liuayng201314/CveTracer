import json
import os
import time
import hashlib
from hashlib import md5
from infrastructure.logging_config import logger


def get_root_path():
    """获取项目根目录路径"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def generate_code_hash(code: str) -> str:
    return hashlib.sha256(code.encode('utf-8')).hexdigest()


def compute_md5_id(content, prefix: str = ""):
    return prefix + md5(content.encode()).hexdigest()


def write_json(json_obj, file_name):
    with open(file_name, "w", encoding="utf-8") as f:
        json.dump(json_obj, f, indent=2, ensure_ascii=False)


def load_json(file_name):
    if not os.path.exists(file_name):
        return None
    with open(file_name, encoding="utf-8") as f:
        return json.load(f)


def compute_args_hash(*args):
    return md5(str(args).encode()).hexdigest()


def measure_time(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        # 计算执行时间（精确到秒，保留3为小数）
        execution_time = round(end_time - start_time, 3)
        logger.info(f"函数 {func.__name__} 执行时间: {execution_time} 秒")
        return result

    return wrapper
