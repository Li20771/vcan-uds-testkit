"""P5 第二阶段：模拟 ECU（CAN 层，单帧 UDS 语义）。

说明：
- 这是「可参数化行为的模拟 ECU」的最小实现，覆盖 TC-UDS-01/02/10/12 的判定所需行为。
- 仅支持单帧（payload ≤ 7 字节）；ISO-TP 多帧待 isotp 可安装后接入（Py3.14 暂无兼容发行版，
  见 99-来源与核验.md 待核验清单）。
- 行为全部可参数化（对照 03-UDS测试模块设计.md §4），便于在临界点两侧各打一条用例。
"""
from __future__ import annotations

import random
import threading
import time
from typing import Callable

REQUEST_ID = 0x7DF
RESPONSE_ID = 0x7E8


class SimEcu:
    """可参数化的模拟 ECU：CAN 层收发 + 最小 UDS 语义。"""

    def __init__(
        self,
        interface: str = "virtual",
        channel: str = "p5uds",
        *,
        max_wrong_key: int = 3,
        lock_seconds: float = 10.0,
        s3_timeout_seconds: float = 2.0,
        seed_algorithm: str = "random",   # random | fixed
        require_session: bool = True,
        vin: bytes = b"P5S",                          # 演示用短值；17 位 VIN 需 ISO-TP 多帧
        recorder: list | None = None,     # 传入共享 list，即可留存全部收发帧（evidence 用）
        on_event: Callable[[str], None] | None = None,
    ) -> None:
        self.bus = __import__("can").interface.Bus(channel, interface=interface)
        self.max_wrong_key = max_wrong_key
        self.lock_seconds = lock_seconds
        self.s3_timeout_seconds = s3_timeout_seconds
        self.seed_algorithm = seed_algorithm
        self.require_session = require_session
        self.vin = vin
        self.recorder = recorder
        self.on_event = on_event or (lambda e: None)

        self.session = 0x01                       # 0x01 默认 / 0x03 扩展
        self.wrong_key_count = 0
        self.unlocked = False
        self._last_seed = b""
        self._last_activity = time.monotonic()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    # ---------------------------------------------------------------- 行为
    def _emit(self, event: str) -> None:
        self.on_event(event)

    def _nrc(self, code: int) -> bytes:
        # 否则响应帧：PCI(0x03) + 7F + SID + NRC
        return bytes([0x03, 0x7F, self._last_sid, code])

    def _handle(self, data: bytes) -> bytes:
        self._last_activity = time.monotonic()           # 任何请求都刷新 S3 计时
        if len(data) < 1:
            return bytes([0x03, 0x7F, 0x00, 0x11])
        service = data[0]
        self._last_sid = service
        if len(data) < 2:
            self._emit("NRC 0x13（长度不足，缺子功能/参数）")
            return bytes([0x03, 0x7F, service, 0x13])
        sub = data[1]

        if service == 0x3E:                                  # TesterPresent
            return bytes([0x02, 0x7E, sub & 0x7F])

        if service == 0x10:                                  # 会话控制
            self.session = {0x01: 0x01, 0x02: 0x02, 0x03: 0x03}.get(sub, 0x01)
            self._emit(f"会话切换 → 0x{self.session:02X}")
            return bytes([0x06, 0x50, sub, 0x00, 0x32, 0x01, 0xF4])

        if service == 0x11:                                  # ECU 复位
            # ⚠️ 安全正确实现：复位【不清零】安全访问尝试计数（TC-UDS-09 的判定点）
            self.session = 0x01
            self.unlocked = False
            self._emit(f"ECU 复位（0x{sub:02X}）→ 回默认会话；锁定计数保留")
            return bytes([0x03, 0x51, sub, 0x00, 0x00, 0x00])

        if service == 0x22:                                  # 读 DID（DID 占 data[1:3]，无子功能）
            if len(data) < 3:
                self._emit("NRC 0x13（DID 长度不足）")
                return bytes([0x03, 0x7F, service, 0x13])
            did = (data[1] << 8) | data[2]
            if did == 0xF190 and (not self.require_session or self.session in (0x03, 0x02)):
                # 演示用 3 字节短值；完整 17 位 VIN 需 ISO-TP 多帧（待 isotp 接入）
                payload = bytes([0x62]) + data[1:3] + self.vin
                return bytes([len(payload)]) + payload
            self._emit(f"读 DID 0x{did:04X} 被拒（会话不符）")
            return self._nrc(0x7F)

        if service == 0x27:                                  # 安全访问
            if self.require_session and self.session != 0x03:
                self._emit("安全访问被拒（会话不符）")
                return self._nrc(0x7F)
            if sub == 0x01:                                  # 请求种子
                self._last_seed = (
                    bytes([0xA1, 0xB2, 0xC3, 0xD4])
                    if self.seed_algorithm == "fixed"
                    else bytes(random.getrandbits(8) for _ in range(4))
                )
                self._emit("发放种子")
                payload = bytes([0x67, 0x01]) + self._last_seed
                return bytes([len(payload)]) + payload
            if sub == 0x02:                                  # 提交密钥
                if self.wrong_key_count >= self.max_wrong_key:
                    self._emit("锁定中（尝试次数超限）")
                    return self._nrc(0x37)
                expected = bytes(b ^ 0xFF for b in self._last_seed)   # 演示用弱算法
                if bytes(data[2:]) == expected:
                    self.wrong_key_count = 0
                    self.unlocked = True
                    self._emit("安全访问解锁")
                    return bytes([0x02, 0x67, 0x02])
                self.wrong_key_count += 1
                self._emit(f"密钥错误 ×{self.wrong_key_count}")
                return self._nrc(0x36 if self.wrong_key_count >= self.max_wrong_key else 0x35)

        if service == 0x2E:                                  # 写 DID（需扩展会话 + 已解锁）
            if len(data) < 4:
                self._emit("NRC 0x13（写 DID 长度不足）")
                return bytes([0x03, 0x7F, service, 0x13])
            did = (data[1] << 8) | data[2]
            if did != 0xF190:
                self._emit(f"写 DID 0x{did:04X} 被拒（不支持该 DID）")
                return self._nrc(0x31)                       # requestOutOfRange
            if self.require_session and self.session != 0x03:
                self._emit("写 DID 被拒（会话不符）")
                return self._nrc(0x7F)
            if not self.unlocked:
                self._emit("写 DID 被拒（未通过安全访问）")
                return self._nrc(0x33)                       # securityAccessDenied
            value = bytes(data[3:])
            if len(value) != 3:                              # 与读侧长度契约一致
                self._emit("NRC 0x13（写入值长度必须为 3 字节）")
                return self._nrc(0x13)
            self.vin = value
            self._emit(f"DID 0xF190 已写入: {value!r}")
            return bytes([0x03, 0x6E, data[1], data[2]])

        self._emit(f"未支持的服务 0x{service:02X}")
        return self._nrc(0x11)

    def _loop(self) -> None:
        while not self._stop.is_set():
            # S3 超时：非默认会话下长时间无请求 → 退回默认会话并上锁
            if (self.session != 0x01
                    and time.monotonic() - self._last_activity > self.s3_timeout_seconds):
                self.session = 0x01
                self.unlocked = False
                self._emit("S3 超时 → 退回默认会话")
            msg = self.bus.recv(timeout=0.1)
            if msg is None or msg.arbitration_id != REQUEST_ID:
                continue
            pci = msg.data[0] if msg.dlc else 0
            if (pci & 0xF0) != 0x0:                          # 只支持单帧
                self._emit("非单帧（ISO-TP 多帧待接入）")
                continue
            if self.recorder is not None:                    # 帧留存（evidence 用）
                self.recorder.append((time.time(), "RX", msg.arbitration_id,
                                      bytes(msg.data).hex()))
            resp = self._handle(msg.data[1:1 + (pci & 0x0F)])
            if self.recorder is not None:
                self.recorder.append((time.time(), "TX", RESPONSE_ID, bytes(resp).hex()))
            self.bus.send(
                __import__("can").Message(
                    arbitration_id=RESPONSE_ID, data=resp, is_extended_id=False
                )
            )

    # ---------------------------------------------------------------- 生命周期
    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.bus.shutdown()
