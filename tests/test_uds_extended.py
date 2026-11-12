"""扩展用例：S3 超时、TesterPresent、ECU 复位与锁定持久性、种子随机性。

对应 03-UDS测试模块设计.md 用例矩阵的 TC-UDS-07/09/13/14 与 0x11 复位行为。
S3 超时用 1 秒短窗口（参数化），测试总时长可控。

响应断言坐标（单帧 PCI 之后的 UDS 数据）：
    resp[0] = SID（正响应 = SID|0x40；否定 = 0x7F）
    resp[1] = 子功能 / 回显 SID
    resp[2] = NRC（仅否定响应）
"""
from __future__ import annotations

import time

import pytest

from uds_module.sim_ecu import SimEcu
from uds_module.uds_client import UdsClient


# ------------------------------------------------------------ 夹具（独立通道）
@pytest.fixture()
def s3_ecu():
    e = SimEcu(interface="virtual", channel="p5s3", s3_timeout_seconds=1.0)
    yield e
    e.stop()


@pytest.fixture()
def s3_client(s3_ecu):
    c = UdsClient(interface="virtual", channel="p5s3", timeout=1.0)
    yield c
    c.shutdown()


def enter_extended(client: UdsClient) -> None:
    resp = client.request(bytes([0x10, 0x03]))
    assert resp is not None and resp[0] == 0x50


def unlock(client: UdsClient) -> None:
    """进入扩展会话 + 用 XOR 0xFF 弱算法解锁（演示算法，故意植入）。"""
    enter_extended(client)
    seed = bytes(client.request(bytes([0x27, 0x01]))[2:])   # 67 01 + seed
    client.request(bytes([0x27, 0x02]) + bytes(b ^ 0xFF for b in seed))


# ---------------------------------------------------------------- TC-UDS-13
def test_tester_present_keeps_session_alive(s3_ecu, s3_client):
    """持续 TesterPresent 时，扩展会话不超时，受保护服务一直可用。"""
    enter_extended(s3_client)
    for _ in range(4):                       # 累计静默间隔 ≈ 1.6s > S3(1s)
        time.sleep(0.4)
        resp = s3_client.request(bytes([0x3E, 0x00]))
        assert resp is not None and resp[0] == 0x7E
    resp = s3_client.request(bytes([0x22, 0xF1, 0x90]))
    assert resp[0] == 0x62, "有保活就不该掉会话"


# ---------------------------------------------------------------- TC-UDS-07
def test_s3_timeout_falls_back_to_default(s3_ecu, s3_client):
    """静置超过 S3 → 自动退回默认会话，扩展服务被拒（7F 22 7F）。"""
    enter_extended(s3_client)
    time.sleep(1.4)                          # 无 TesterPresent
    resp = s3_client.request(bytes([0x22, 0xF1, 0x90]))
    assert resp is not None and resp[0] == 0x7F, "S3 超时后应退回默认会话"


# ---------------------------------------------------------------- TC-UDS-14
def test_seed_is_not_fixed(ecu: SimEcu, client: UdsClient):
    """连续两次请求种子必须不同——固定种子 = 可推导密钥（缺陷）。"""
    enter_extended(client)
    s1 = bytes(client.request(bytes([0x27, 0x01]))[2:])      # 67 01 + seed
    s2 = bytes(client.request(bytes([0x27, 0x01]))[2:])
    assert len(s1) == 4
    assert s1 != s2, "两次种子相同 → 种子可预测（缺陷）"


# ---------------------------------------------------------------- 0x11 复位语义
def test_reset_clears_session_and_unlock(ecu: SimEcu, client: UdsClient):
    """复位后：会话回默认、解锁状态失效（正向语义）。"""
    unlock(client)
    resp = client.request(bytes([0x22, 0xF1, 0x90]))
    assert resp[0] == 0x62                                   # 解锁状态下可读
    resp = client.request(bytes([0x11, 0x01]))
    assert resp is not None and resp[0] == 0x51              # 51 01 = hardReset 正响应
    resp = client.request(bytes([0x22, 0xF1, 0x90]))
    assert resp[0] == 0x7F, "复位后必须回到默认会话，扩展服务被拒"


# ---------------------------------------------------------------- TC-UDS-09
def test_lock_survives_ecu_reset(ecu: SimEcu, client: UdsClient):
    """锁定期间复位 ECU，尝试计数必须保留——否则攻击者可'复位洗白'后继续爆破。"""
    enter_extended(client)
    for _ in range(3):                                       # 3 次错密钥 → 达到锁定阈值
        seed = bytes(client.request(bytes([0x27, 0x01]))[2:])
        resp = client.request(bytes([0x27, 0x02]) + bytes(b ^ 0x00 for b in seed))
        assert resp[0] == 0x7F

    resp = client.request(bytes([0x11, 0x01]))               # 复位
    assert resp[0] == 0x51

    enter_extended(client)                                   # 重新进扩展会话
    seed = bytes(client.request(bytes([0x27, 0x01]))[2:])
    resp = client.request(bytes([0x27, 0x02]) + bytes(b ^ 0xFF for b in seed))
    # 发"正确密钥"仍应被 0x37 拒绝——锁定计数跨复位保留
    assert resp[0] == 0x7F and resp[2] == 0x37, \
        "复位清零了尝试计数 = 缺陷（TC-UDS-09）：攻击者可复位洗白后继续爆破"
