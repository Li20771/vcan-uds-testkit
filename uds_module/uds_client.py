"""UDS 客户端封装：构造单帧请求、等待响应、断言辅助。"""
from __future__ import annotations

import time

import can

REQUEST_ID = 0x7DF
RESPONSE_ID = 0x7E8


class UdsClient:
    """CAN 层单帧 UDS 客户端（ISO-TP 多帧待 isotp 可安装后接入）。

    recorder：传入共享 list 即可留存全部收发帧（evidence 用）。
    """

    def __init__(self, interface: str = "virtual", channel: str = "p5uds",
                 timeout: float = 1.0, recorder: list | None = None) -> None:
        self.bus = can.interface.Bus(channel, interface=interface)
        self.timeout = timeout
        self.recorder = recorder

    def request(self, payload: bytes) -> bytes | None:
        """发 0x7DF 单帧请求，返回 0x7E8 响应的数据段（去 PCI 后的 UDS 数据）；超时返回 None。"""
        if len(payload) > 7:
            raise ValueError("当前仅支持单帧（payload ≤ 7 字节）")
        frame = bytes([len(payload)]) + payload
        if self.recorder is not None:
            self.recorder.append((time.time(), "TX", REQUEST_ID, frame.ljust(8, b"\x00").hex()))
        self.bus.send(can.Message(arbitration_id=REQUEST_ID, data=frame.ljust(8, b"\x00"),
                                  is_extended_id=False))
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            msg = self.bus.recv(timeout=0.1)
            if msg is None or msg.arbitration_id != RESPONSE_ID:
                continue
            if self.recorder is not None:
                self.recorder.append((time.time(), "RX", RESPONSE_ID, bytes(msg.data).hex()))
            return bytes(msg.data[1:1 + msg.data[0]])
        return None

    def shutdown(self) -> None:
        self.bus.shutdown()
