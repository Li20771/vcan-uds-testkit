"""pytest 夹具 + 证据链基础设施。

每次运行自动创建 evidence/RUN-<时间戳>/：
  frames.csv   全部 CAN 收发帧（时间戳/方向/ID/数据）
  pytest.xml   JUnit 格式结果（机器可读）
  env.txt      环境声明（Python / 库版本 / 平台 / 时间）
  sha256.txt   上述文件的哈希清单（防篡改质疑）
"""
from __future__ import annotations

import hashlib
import importlib
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

# 让 tests/ 找到 uds_module/（不要求安装为包）
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from uds_module.sim_ecu import SimEcu          # noqa: E402
from uds_module.uds_client import UdsClient    # noqa: E402

PROJECT = Path(__file__).resolve().parents[1]
_recorder: list = []          # 共享帧记录器：一个会话一个 RUN
_evidence: Path | None = None


def _evidence_dir() -> Path:
    global _evidence
    if _evidence is None:
        _evidence = PROJECT / "evidence" / ("RUN-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
        _evidence.mkdir(parents=True, exist_ok=True)
    return _evidence


def _lib_version(name: str) -> str:
    try:
        m = importlib.import_module(name)
        return getattr(m, "__version__", "?")
    except Exception:
        return "未安装"


def pytest_configure(config):
    """无 --junitxml 时自动落一份到本 RUN 目录（机器可读结果）。"""
    if not getattr(config.option, "xmlpath", None):
        config.option.xmlpath = str(_evidence_dir() / "pytest.xml")


def pytest_sessionfinish(session, exitstatus):
    """会话结束：写 frames.csv / env.txt / sha256.txt（三件证据）。"""
    d = _evidence_dir()

    if _recorder:                                            # ① 帧记录
        with open(d / "frames.csv", "w", encoding="utf-8") as f:
            f.write("unix_time,direction,arbitration_id,data_hex\n")
            for ts, drc, aid, hex_ in sorted(_recorder, key=lambda x: x[0]):
                f.write(f"{ts:.6f},{drc},0x{aid:03X},{hex_}\n")

    (d / "env.txt").write_text(                              # ② 环境声明
        "\n".join([
            f"run_dir        : {d.name}",
            f"finished_at    : {datetime.now(timezone.utc).isoformat()}",
            f"python         : {sys.version.split()[0]} ({platform.platform()})",
            f"python-can     : {_lib_version('can')}",
            f"cantools       : {_lib_version('cantools')}",
            f"udsoncan       : {_lib_version('udsoncan')}",
            f"pytest         : {_lib_version('pytest')}",
            f"frames_recorded: {len(_recorder)}",
            f"exit_status    : {exitstatus}",
        ]) + "\n", encoding="utf-8")

    lines = []                                               # ③ 哈希清单
    for p in sorted(d.iterdir()):
        if p.is_file() and p.name != "sha256.txt":
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            lines.append(f"{h}  {p.name}")
    (d / "sha256.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------- 夹具
@pytest.fixture()
def ecu():
    e = SimEcu(interface="virtual", channel="p5uds",
               max_wrong_key=3, lock_seconds=10.0, seed_algorithm="random",
               recorder=_recorder)
    yield e
    e.stop()


@pytest.fixture()
def client(ecu):
    c = UdsClient(interface="virtual", channel="p5uds", timeout=1.0,
                  recorder=_recorder)
    yield c
    c.shutdown()


# ---------------------------------------------------------------- 扩展用例夹具（独立通道）
@pytest.fixture()
def s3_ecu():
    e = SimEcu(interface="virtual", channel="p5s3", s3_timeout_seconds=1.0,
               recorder=_recorder)
    yield e
    e.stop()


@pytest.fixture()
def s3_client(s3_ecu):
    c = UdsClient(interface="virtual", channel="p5s3", timeout=1.0,
                  recorder=_recorder)
    yield c
    c.shutdown()
