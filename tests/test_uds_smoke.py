"""冒烟测试：验证「客户端 → 模拟 ECU」链路与最小 UDS 语义。

对应 03-UDS测试模块设计.md 用例矩阵的 TC-UDS-01/02/10/12 与锁定临界点 TC-UDS-04/05/06。
注意：种子-密钥的演示算法是 XOR 0xFF（弱算法）——**故意植入**，用于演示
"种子可预测 → 可推导密钥"这类缺陷如何被用例证实（见设计文档 §5 安全视角）。

响应帧的断言坐标（单帧 PCI 之后的 UDS 数据）：
    resp[0] = SID（正响应 = SID|0x40；否定 = 0x7F）
    resp[1] = 子功能 / 回显 SID
    resp[2] = NRC（仅否定响应）
"""
from __future__ import annotations

import pytest

from uds_module.sim_ecu import SimEcu
from uds_module.uds_client import UdsClient


# ---------------------------------------------------------------- TC-UDS-01
def test_session_control_extended(client: UdsClient):
    """10 03 → 正响应 50 03。"""
    resp = client.request(bytes([0x10, 0x03]))
    assert resp is not None, "超时无响应"
    assert resp[0] == 0x50 and resp[1] == 0x03


# ---------------------------------------------------------------- TC-UDS-02
def test_security_access_denied_in_default_session(client: UdsClient):
    """默认会话下请求种子 → 7F 27 7F（越权被拒）。"""
    resp = client.request(bytes([0x27, 0x01]))
    assert resp is not None
    assert resp[0] == 0x7F and resp[1] == 0x27 and resp[2] == 0x7F


# ---------------------------------------------------------------- TC-UDS-12
def test_unsupported_service_rejected(client: UdsClient):
    """未支持的服务 0x99 00 → 7F 99 11。"""
    resp = client.request(bytes([0x99, 0x00]))
    assert resp is not None
    assert resp[0] == 0x7F and resp[1] == 0x99 and resp[2] == 0x11


# ---------------------------------------------------------------- TC-UDS-10
def test_missing_subfunction_nrc_0x13(client: UdsClient):
    """27 后缺子功能 → 7F 27 13（长度校验）。"""
    resp = client.request(bytes([0x27]))
    assert resp is not None
    assert resp[0] == 0x7F and resp[1] == 0x27 and resp[2] == 0x13


# ---------------------------------------------------------------- 读 VIN（短值）
def test_read_vin_in_extended_session(ecu: SimEcu, client: UdsClient):
    """22 F1 90 在扩展会话下返回演示 VIN（3 字节短值，完整 17 位需 ISO-TP 多帧）。"""
    client.request(bytes([0x10, 0x03]))
    resp = client.request(bytes([0x22, 0xF1, 0x90]))
    assert resp is not None and resp[0] == 0x62
    assert bytes(resp[3:]) == b"P5S"


# ---------------------------------------------- 锁定临界点（故意植入的弱算法）
@pytest.mark.parametrize(
    "wrong_attempts,expect_unlock",
    [(2, True), (3, False), (4, False)],
    ids=["2次→可解锁", "3次→已达阈值锁定", "4次→锁定"],
)
def test_wrong_key_threshold(ecu: SimEcu, client: UdsClient,
                             wrong_attempts: int, expect_unlock: bool):
    """TC-UDS-04/05/06：错密钥 N 次后再发正确密钥，临界点两侧行为必须不同。"""
    client.request(bytes([0x10, 0x03]))                      # 进扩展会话
    seed_resp = client.request(bytes([0x27, 0x01]))
    assert seed_resp is not None and seed_resp[0] == 0x67
    seed = bytes(seed_resp[2:])      # ⚠️ 响应布局 = 67 01 + seed，种子从 index 2 开始
    key = bytes(b ^ 0xFF for b in seed)

    for _ in range(wrong_attempts):                          # 先发 N 次错密钥
        bad = bytes(b ^ 0x00 for b in seed)
        resp = client.request(bytes([0x27, 0x02]) + bad)
        assert resp[0] == 0x7F

    resp = client.request(bytes([0x27, 0x02]) + key)         # 最后发正确密钥
    if expect_unlock:
        assert resp[0] == 0x67, f"错 {wrong_attempts} 次（<3）仍应可解锁"
    else:
        assert resp[0] == 0x7F, f"错 {wrong_attempts} 次（≥3）必须锁定"
