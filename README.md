# vcan-uds-testkit

> **定位**：python-can virtual 总线上的 UDS 诊断安全测试套件（模拟 ECU + 单帧客户端 + 18 条 pytest 用例 + 运行证据链）
> **技能**：UDS（0x10/0x11/0x22/0x27/0x2E/0x3E）、安全访问锁定、pytest、证据链（帧/JUnit/哈希）
> **证据**：18 passed（RUN-20261112-140253：frames.csv + pytest.xml + env.txt + sha256.txt）
> **复现**：`pip install -r requirements.txt && python -m pytest -q`
> **边界**：仿真环境，不适用于真实车辆/ECU；ISO-TP 多帧未接入
> **维护**：稳定（2026-11-12 发布，MIT）


基于 python-can **virtual 总线**的 UDS（ISO 14229）诊断安全测试套件：一个行为可参数化的模拟 ECU、一个单帧 UDS 客户端、18 条 pytest 用例，以及一条「帧记录 + JUnit XML + 环境声明 + SHA-256 清单」的运行证据链。

> 定位声明：本项目用于**教学与仿真环境**中的诊断访问控制测试练习，不针对、也不适用于任何真实车辆、真实 ECU 或任何产品。

## 解决什么问题

没有硬件时，如何练习并验证诊断访问控制的设计是否有效：

- 会话控制（0x10）：扩展会话进入/退出；受保护服务在默认会话下的拒绝（NRC 0x7F）
- 安全访问（0x27）：错误密钥尝试计数与锁定临界点（2/3/4 次参数化验证），NRC 0x35/0x36/0x37
- 锁定状态跨 ECU 复位（0x11）保留——「复位洗白」缺陷的否定证明
- S3 会话超时回退、TesterPresent（0x3E）保活、种子随机性（两次种子必须不同）
- 写服务（0x2E）三重门：会话（0x7F）→ 安全解锁（0x33）→ 值长度（0x13）；写后读回验证
- 模拟 ECU **故意植入** XOR 0xFF 弱种子-密钥算法（教学缺陷），演示「种子可推导 → 密钥可计算」如何被用例钉死

## 快速开始

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate     Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
```

每次运行会在 `evidence/RUN-<时间戳>/` 自动生成四件证据：`frames.csv`（全部 CAN 收发帧）、`pytest.xml`（JUnit 机器可读结果）、`env.txt`（Python/库版本/平台）、`sha256.txt`（哈希清单）。

## 目录结构

```text
vcan-uds-testkit/
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
├── uds_module/
│   ├── __init__.py
│   ├── sim_ecu.py        # 模拟 ECU：CAN 层收发 + 最小 UDS 语义（行为可参数化）
│   └── uds_client.py     # UDS 客户端：单帧请求/响应 + 帧记录
├── tests/
│   ├── conftest.py       # pytest 夹具 + 证据链基础设施（自动落盘 RUN 目录）
│   ├── test_uds_smoke.py       # 链路冒烟 + 锁定临界点（含参数化 2/3/4 次）
│   ├── test_uds_extended.py    # S3 超时 / TesterPresent / 复位语义 / 锁定持久性
│   └── test_uds_write.py       # 0x2E 写服务：三重门 + 写后读回
└── evidence/
    └── RUN-20261112-140253/    # 一次真实运行的完整证据包（见下）
```

## 证据

**evidence/RUN-20261112-140253**（运行日期 2026-11-12）：

- `pytest.xml`：**18 tests / 0 failures / 0 errors / 0 skipped**，总时长 5.022 s
- `frames.csv`：244 帧 CAN 收发记录（客户端 TX/RX 与 ECU RX/TX 双视角）
- `env.txt`：Python 3.12.14（Windows）· python-can 4.6.1 · pytest 9.2.0 · udsoncan 1.26.1
- `sha256.txt`：上述三个文件的 SHA-256 清单
- 说明：`pytest.xml` 中的 `hostname` 属性已脱敏为 `localhost`，`sha256.txt` 为脱敏后副本重算的清单

**本机复跑记录**（2026-11-12，Python 3.12.0 / python-can 4.6.1 / pytest 9.2.0）：`python -m pytest -q` → **18 passed in 5.18s**，退出码 0。

## Status

- **已完成**：6 个 UDS 服务（0x10 / 0x11 / 0x22 / 0x27 / 0x2E / 0x3E）的 18 条用例全部通过；证据链（帧 / 结果 / 环境 / 哈希）自动落盘。
- **未完成**：ISO-TP 多帧未接入（当前仅支持单帧，payload ≤ 7 字节；`isotp` / `udsoncan` 已列入 requirements 供后续接入，其中 isotp 在本机所用镜像不可得，验证时装了其余依赖）；未在任何真实硬件上验证（也不计划如此——本套件定位即仿真）。

## License

MIT（见 LICENSE）。

---

**English TL;DR:** A teaching-oriented UDS (ISO 14229) diagnostic security test kit running on python-can's virtual bus: a parameterizable simulated ECU, a single-frame UDS client, 18 pytest cases (session control, security-access lockout thresholds, reset-persistent lockout, S3 timeout, write-service triple gate), and an evidence chain (frames.csv + JUnit XML + env.txt + SHA-256 manifest). Packaged run RUN-20261112-140253 (2026-11-12): 18 passed / 0 failed in 5.0 s; re-run locally on 2026-11-12: 18 passed. ISO-TP multi-frame and real-hardware validation are not implemented. Simulation only — not applicable to real vehicles.
