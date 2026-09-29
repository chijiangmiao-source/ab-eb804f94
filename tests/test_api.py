"""端到端测试：真实 HTTP 服务 + 文件存储，覆盖三类必备场景与冻结语义。"""

import json
import os
import tempfile
import threading
import unittest
import urllib.request
import urllib.error

from app.server import build_server


def req(method, url, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    r = urllib.request.Request(url, data=data, method=method,
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.httpd = build_server(host="127.0.0.1", port=0, data_dir=cls.tmp.name)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        # 每个用例使用独立 audit_id，互不干扰
        self.audit = f"audit-{self._testMethodName}"

    def _rule(self, rid, proto, src, dst, sp, dp):
        return {"rule_id": rid, "protocol": proto,
                "src_cidr": src, "dst_cidr": dst,
                "src_port": list(sp), "dst_port": list(dp)}

    def _payload(self, rules, audit=None):
        return {"audit_id": audit or self.audit, "rules": rules}

    def test_health(self):
        status, body = req("GET", f"{self.base}/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_partial_and_full_coverage_flow(self):
        rules = [
            # R1 仅 TCP 全域
            self._rule("R1", "TCP", "0.0.0.0/0", "0.0.0.0/0",
                       (0, 65535), (0, 65535)),
            # R2 部分遮蔽：BOTH 全域，UDP 部分仍可命中 → 最小见证为 UDP 全域最点
            self._rule("R2", "BOTH", "0.0.0.0/0", "0.0.0.0/0",
                       (0, 65535), (0, 65535)),
            # R3 完全遮蔽：TCP 一窄条，被 R1 完全覆盖
            self._rule("R3", "TCP", "10.0.0.0/8", "192.168.0.0/16",
                       (1000, 2000), (443, 443)),
        ]
        status, body = req("POST", f"{self.base}/api/audits", self._payload(rules))
        self.assertEqual(status, 201, body)
        d = {x["rule_id"]: x for x in body["decisions"]}

        self.assertEqual(d["R1"]["verdict"], "PARTIALLY_COVERED")
        self.assertEqual(d["R1"]["witness"]["protocol"], "TCP")
        self.assertEqual(d["R1"]["witness"]["src_addr"], "0.0.0.0")

        self.assertEqual(d["R2"]["verdict"], "PARTIALLY_COVERED")
        # 剩余只剩 UDP（协议维 1 > TCP 0），最小见证协议必为 UDP
        self.assertEqual(d["R2"]["witness"]["protocol"], "UDP")
        self.assertEqual(d["R2"]["witness"]["src_addr"], "0.0.0.0")
        self.assertEqual(d["R2"]["witness"]["dst_addr"], "0.0.0.0")
        self.assertEqual(d["R2"]["witness"]["src_port"], 0)
        self.assertEqual(d["R2"]["witness"]["dst_port"], 0)

        self.assertEqual(d["R3"]["verdict"], "FULLY_COVERED")
        # R3 的点同时落在 R1(TCP 全域) 与 R2(BOTH 全域) 内
        self.assertEqual(d["R3"]["covered_by"], ["R1", "R2"])
        self.assertIsNone(d["R3"]["witness"])

        # 冻结后按标识重新查看，结论一致
        status2, fetched = req("GET", f"{self.base}/api/audits/{self.audit}")
        self.assertEqual(status2, 200)
        self.assertEqual(fetched["decisions"], body["decisions"])
        self.assertEqual(fetched["rules"], body["rules"])

    def test_partial_cover_with_cidr_and_port_remainder(self):
        rules = [
            self._rule("R1", "BOTH", "10.0.0.0/8", "192.168.0.0/16",
                       (100, 200), (80, 80)),
            # R2 与 R1 同协议，源缩小、目的扩大，端口扩大 → 部分遮蔽
            self._rule("R2", "BOTH", "10.1.0.0/16", "192.168.0.0/16",
                       (100, 300), (80, 81)),
        ]
        status, body = req("POST", f"{self.base}/api/audits", self._payload(rules))
        self.assertEqual(status, 201, body)
        d2 = body["decisions"][1]
        self.assertEqual(d2["verdict"], "PARTIALLY_COVERED")
        w = d2["witness"]
        # 剩余：src 10.1.0.0/16 内 sport 201..300 或 dport 81；
        # 五维排序最小点 = (BOTH 中 TCP, 10.1.0.0, 192.168.0.0, sport 100, dport 81)
        self.assertEqual(w["protocol"], "TCP")
        self.assertEqual(w["src_addr"], "10.1.0.0")
        self.assertEqual(w["dst_addr"], "192.168.0.0")
        self.assertEqual(w["src_port"], 100)
        self.assertEqual(w["dst_port"], 81)

    def test_full_cover_by_two_earlier_rules(self):
        rules = [
            self._rule("T", "TCP", "0.0.0.0/0", "0.0.0.0/0",
                       (0, 65535), (0, 65535)),
            self._rule("U", "UDP", "0.0.0.0/0", "0.0.0.0/0",
                       (0, 65535), (0, 65535)),
            self._rule("M", "BOTH", "172.16.0.0/12", "8.8.8.8/32",
                       (53, 53), (53, 53)),
        ]
        status, body = req("POST", f"{self.base}/api/audits", self._payload(rules))
        self.assertEqual(status, 201, body)
        m = body["decisions"][2]
        self.assertEqual(m["verdict"], "FULLY_COVERED")
        self.assertEqual(m["covered_by"], ["T", "U"])

    def test_illegal_retransmit_rejected_and_frozen_kept(self):
        rules = [self._rule("R1", "TCP", "10.0.0.0/8", "0.0.0.0/0",
                            (0, 65535), (0, 65535))]
        status, body = req("POST", f"{self.base}/api/audits", self._payload(rules))
        self.assertEqual(status, 201)
        original = body

        # 同一 audit_id 改换载荷（端口变化）→ 409，既有结论不动
        changed = self._payload([
            self._rule("R1", "TCP", "10.0.0.0/8", "0.0.0.0/0",
                       (1, 65535), (0, 65535))])
        status, body = req("POST", f"{self.base}/api/audits", changed)
        self.assertEqual(status, 409)
        self.assertIn("拒绝改写", body["error"])

        status, fetched = req("GET", f"{self.base}/api/audits/{self.audit}")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["decisions"], original["decisions"])
        self.assertEqual(fetched["rules"][0]["src_port"], [0, 65535])

    def test_identical_retransmit_is_idempotent(self):
        rules = [self._rule("R1", "UDP", "10.0.0.0/8", "10.0.0.0/8",
                            (0, 1024), (0, 1024))]
        payload = self._payload(rules)
        s1, b1 = req("POST", f"{self.base}/api/audits", payload)
        self.assertEqual(s1, 201)
        s2, b2 = req("POST", f"{self.base}/api/audits", payload)
        self.assertEqual(s2, 200)
        self.assertTrue(b2["identical_resubmission"])
        self.assertEqual(b2["decisions"], b1["decisions"])

    def test_invalid_payloads_rejected(self):
        bad_cases = [
            self._payload([self._rule("R1", "TCP", "10.0.0.1/24",
                                      "0.0.0.0/0", (0, 1), (0, 1))]),
            self._payload([self._rule("R1", "ICMP", "0.0.0.0/0",
                                      "0.0.0.0/0", (0, 1), (0, 1))]),
            self._payload([self._rule("R1", "TCP", "0.0.0.0/0",
                                      "0.0.0.0/0", (70000, 70001), (0, 1))]),
            self._payload([self._rule("R1", "TCP", "0.0.0.0/0",
                                      "0.0.0.0/0", (9, 8), (0, 1))]),
        ]
        for payload in bad_cases:
            status, body = req("POST", f"{self.base}/api/audits", payload)
            self.assertEqual(status, 400, body)

        # 重复规则标识
        dup = self._payload([
            self._rule("R1", "TCP", "0.0.0.0/0", "0.0.0.0/0", (0, 1), (0, 1)),
            self._rule("R1", "UDP", "0.0.0.0/0", "0.0.0.0/0", (0, 1), (0, 1)),
        ])
        status, body = req("POST", f"{self.base}/api/audits", dup)
        self.assertEqual(status, 400)
        self.assertIn("重复", body["error"])

    def test_get_unknown_audit(self):
        status, _ = req("GET", f"{self.base}/api/audits/no-such-thing")
        self.assertEqual(status, 404)

    def test_static_page_served(self):
        with urllib.request.urlopen(f"{self.base}/", timeout=10) as resp:
            html = resp.read().decode("utf-8")
        self.assertIn("报文规则遮蔽审计", html)
        with urllib.request.urlopen(f"{self.base}/static/app.js", timeout=10) as resp:
            js = resp.read().decode("utf-8")
        self.assertIn("/api/audits", js)


if __name__ == "__main__":
    unittest.main()
