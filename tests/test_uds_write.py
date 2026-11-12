"""0x2E WriteDataByIdentifier 用例（六服务覆盖的最后一格）。

安全语义（模拟 ECU 的检查顺序）：
    长度 → DID 支持 → 会话（0x7F）→ 安全访问解锁（0x33）→ 值长度（0x13）
正向写入后必须「读回验证」——写入成功 ≠ 写入生效。
"""
from __future__ import annotations

import pytest

from uds_module.uds_client import UdsClient


def unlock(client: UdsClient) -> None:
    """进扩展会话 + XOR 0xFF 弱算法解锁（演示算法，故意植入）。"""
    resp = client.request(bytes([0x10, 0x03]))
    assert resp is not None and resp[0] == 0x50
    seed = bytes(client.request(bytes([0x27, 0x01]))[2:])    # 67 01 + seed
    resp = client.request(bytes([0x27, 0x02]) + bytes(b ^ 0xFF for b in seed))
    assert resp is not None and resp[0] == 0x67


# --------------------------------------------------- 会话校验（默认会话拒绝）
def test_write_denied_in_default_session(client: UdsClient):
    """默认会话下写 DID → 7F 2E 7F（会话不符）。"""
    resp = client.request(bytes([0x2E, 0xF1, 0x90]) + b"P5X")
    assert resp is not None
    assert resp[0] == 0x7F and resp[1] == 0x2E and resp[2] == 0x7F


# --------------------------------------------------- 安全访问校验（未解锁拒绝）
def test_write_denied_without_security_unlock(client: UdsClient):
    """扩展会话但未解锁 → 7F 2E 33（securityAccessDenied）。"""
    client.request(bytes([0x10, 0x03]))                      # 只切会话，不解锁
    resp = client.request(bytes([0x2E, 0xF1, 0x90]) + b"P5X")
    assert resp is not None
    assert resp[0] == 0x7F and resp[1] == 0x2E and resp[2] == 0x33


# --------------------------------------------------- 正向写入 + 读回验证
def test_write_then_read_back(ecu, client: UdsClient):
    """解锁后写 DID → 正响应 6E；读回值必须等于写入值（写入生效才算过）。"""
    unlock(client)
    resp = client.request(bytes([0x2E, 0xF1, 0x90]) + b"P5X")
    assert resp is not None
    assert resp[0] == 0x6E and resp[1] == 0xF1 and resp[2] == 0x90

    back = client.request(bytes([0x22, 0xF1, 0x90]))         # 读回验证
    assert back is not None and back[0] == 0x62
    assert bytes(back[3:]) == b"P5X", "写后读回不一致——写入未生效"


# --------------------------------------------------- 值长度校验
def test_write_wrong_value_length(ecu, client: UdsClient):
    """写入值 2 字节（契约要求 3 字节）→ NRC 0x13，且原值不被破坏。"""
    unlock(client)
    resp = client.request(bytes([0x2E, 0xF1, 0x90]) + b"AB")
    assert resp is not None
    assert resp[0] == 0x7F and resp[2] == 0x13
    back = client.request(bytes([0x22, 0xF1, 0x90]))
    assert bytes(back[3:]) == b"P5S", "被拒的写入不得破坏原值"


# --------------------------------------------------- DID 支持校验
def test_write_unsupported_did(ecu, client: UdsClient):
    """不支持的 DID 0x1234 → NRC 0x31（requestOutOfRange）。"""
    unlock(client)
    resp = client.request(bytes([0x2E, 0x12, 0x34]) + b"ABC")
    assert resp is not None
    assert resp[0] == 0x7F and resp[1] == 0x2E and resp[2] == 0x31
