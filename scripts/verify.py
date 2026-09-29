#!/usr/bin/env python3
"""Compose verify 服务入口：
1) 构建检查：全部源码字节码编译 + 关键模块导入；
2) 代码测试：unittest 全套；
3) HTTP 冒烟：健康端点、部分遮蔽、完全遮蔽、非法重传、非法载荷。
任一步失败即以非零退出码上报。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

BASE_URL = os.environ.get("BASE_URL", "http://web:8080")
FAILURES: list[str] = []


def step(name):
    print(f"\n=== verify: {name} ===", flush=True)


def check(cond, ok_msg, bad_msg):
    if cond:
        print(f"  PASS  {ok_msg}")
    else:
        print(f"  FAIL  {bad_msg}")
        FAILURES.append(bad_msg)


def http(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE_URL + path, data=data, method=method,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def rule(rid, proto, src, dst, sp, dp):
    return {"rule_id": rid, "protocol": proto,
            "src_cidr": src, "dst_cidr": dst,
            "src_port": list(sp), "dst_port": list(dp)}


def build_check():
    step("构建检查（compileall + import）")
    rc = subprocess.run([sys.executable, "-m", "compileall", "-q", "app", "tests"],
                        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    check(rc.returncode == 0, "源码全部通过字节码编译", "compileall 失败")
    rc = subprocess.run([sys.executable, "-c", "import app.server, app.geometry, app.rules, app.storage"])
    check(rc.returncode == 0, "关键模块导入成功", "关键模块导入失败")


def unit_tests():
    step("代码测试（unittest）")
    rc = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"])
    check(rc.returncode == 0, "unittest 全部通过", "unittest 存在失败用例")


def smoke():
    step(f"HTTP 冒烟（{BASE_URL}）")

    status, body = http("GET", "/health")
    check(status == 200 and body.get("status") == "ok",
          f"健康端点可用 {body}", f"健康端点异常 status={status} body={body}")

    audit_id = "verify-smoke-" + os.environ.get("VERIFY_RUN_ID", "1")
    payload = {
        "audit_id": audit_id,
        "rules": [
            # 部分遮蔽：R1 仅 TCP 全域，R2 BOTH 全域（UDP 部分剩余）
            rule("R1", "TCP", "0.0.0.0/0", "0.0.0.0/0", (0, 65535), (0, 65535)),
            rule("R2", "BOTH", "0.0.0.0/0", "0.0.0.0/0", (0, 65535), (0, 65535)),
            # 完全遮蔽：R3 TCP 窄条，被 R1/R2 完全覆盖
            rule("R3", "TCP", "10.0.0.0/8", "192.168.0.0/16", (1000, 2000), (443, 443)),
        ],
    }
    status, body = http("POST", "/api/audits", payload)
    check(status == 201, f"提交成功 status={status}", f"提交失败 status={status} body={body}")
    decisions = {d["rule_id"]: d for d in body.get("decisions", [])}

    r2 = decisions.get("R2", {})
    check(r2.get("verdict") == "PARTIALLY_COVERED"
          and r2.get("witness", {}).get("protocol") == "UDP"
          and r2["witness"]["src_addr"] == "0.0.0.0",
          f"部分遮蔽裁决正确，最小见证={r2.get('witness')}",
          f"部分遮蔽裁决错误: {r2}")

    r3 = decisions.get("R3", {})
    check(r3.get("verdict") == "FULLY_COVERED"
          and set(r3.get("covered_by", [])) >= {"R1", "R2"}
          and r3.get("witness") is None,
          f"完全遮蔽裁决正确，覆盖者={r3.get('covered_by')}",
          f"完全遮蔽裁决错误: {r3}")

    # 冻结结论可按审计标识重新查看
    status, fetched = http("GET", f"/api/audits/{audit_id}")
    check(status == 200 and fetched.get("decisions") == body["decisions"],
          "冻结结论可重新查看且一致", f"冻结结论查询异常 status={status}")

    # 非法重传：同一审计标识改换载荷（改端口），必须 409 且不动既有结论
    changed = json.loads(json.dumps(payload))
    changed["rules"][0]["src_port"] = [1, 65535]
    status, body409 = http("POST", "/api/audits", changed)
    check(status == 409 and "拒绝改写" in body409.get("error", ""),
          f"改换载荷被 409 拒绝: {body409.get('error')}",
          f"非法重传未被拒绝 status={status} body={body409}")

    status, still = http("GET", f"/api/audits/{audit_id}")
    check(still["rules"][0]["src_port"] == [0, 65535],
          "既有冻结结论未被改写", "既有结论被非法重传改写！")

    # 非法 CIDR（主机位非零）必须 400
    bad = {"audit_id": audit_id + "-bad", "rules": [
        rule("X", "TCP", "10.0.0.1/24", "0.0.0.0/0", (0, 1), (0, 1))]}
    status, body400 = http("POST", "/api/audits", bad)
    check(status == 400, f"非法 CIDR 被 400 拒绝: {body400.get('error')}",
          f"非法 CIDR 未被拒绝 status={status}")

    # 重复规则标识也必须 400
    dup = {"audit_id": audit_id + "-dup", "rules": [
        rule("X", "TCP", "0.0.0.0/0", "0.0.0.0/0", (0, 1), (0, 1)),
        rule("X", "UDP", "0.0.0.0/0", "0.0.0.0/0", (0, 1), (0, 1))]}
    status, body_dup = http("POST", "/api/audits", dup)
    check(status == 400 and "重复" in body_dup.get("error", ""),
          f"重复规则标识被 400 拒绝: {body_dup.get('error')}",
          f"重复规则标识未被拒绝 status={status}")


def main():
    build_check()
    unit_tests()
    smoke()
    print("\n=== verify 汇总 ===")
    if FAILURES:
        print(f"FAILED：{len(FAILURES)} 项未通过")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("ALL CHECKS PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
