"""几何引擎测试：差集分片、不相交不变量、与逐点枚举的一致性、覆盖属主。"""

import itertools
import unittest

from app.geometry import Box, BoxList, bounds_from_rule
from app.rules import Rule, adjudicate, parse_audit


def B(proto=(0, 1), src=(0, 2**32 - 1), dst=(0, 2**32 - 1),
      sport=(0, 65535), dport=(0, 65535)):
    return (proto, src, dst, sport, dport)


def in_bounds(point, bounds):
    return all(bounds[d][0] <= point[d] <= bounds[d][1] for d in range(5))


def pairwise_disjoint(boxes):
    for i, a in enumerate(boxes):
        for b in boxes[i + 1:]:
            if all(max(a.bounds[d][0], b.bounds[d][0])
                   <= min(a.bounds[d][1], b.bounds[d][1]) for d in range(5)):
                return False
    return True


class GeometryTests(unittest.TestCase):
    def test_subtract_keeps_outside_pieces_and_disjointness(self):
        union = BoxList.empty()
        union.add(B(proto=(0, 0), src=(0, 100), dst=(0, 100),
                    sport=(0, 100), dport=(0, 100)), "A")
        union.add(B(proto=(0, 0), src=(50, 150), dst=(50, 150),
                    sport=(50, 150), dport=(50, 150)), "B")
        self.assertTrue(pairwise_disjoint(union.boxes))

        # 重叠区域（五维都落在 [50,100] 协议 TCP）属主必须同时包含 A 与 B
        overlap = [bx for bx in union.boxes
                   if all(bx.bounds[d][0] >= 50 and bx.bounds[d][1] <= 100
                          for d in range(1, 5))
                   and bx.bounds[0] == (0, 0)]
        self.assertTrue(overlap)
        for bx in overlap:
            self.assertIn("A", bx.owners)
            self.assertIn("B", bx.owners)

        # A 独有区域属主只有 A
        only_a = [bx for bx in union.boxes if bx.bounds[1][1] < 50]
        self.assertTrue(only_a)
        for bx in only_a:
            self.assertEqual(bx.owners, frozenset({"A"}))

    def test_membership_matches_point_enumeration(self):
        """小规模空间中逐点枚举：并集盒子与规则盒子的点成员关系完全一致。"""
        # 协议 2 × 源地址 4（/30）× 目的地址 4 × 源端口 10 × 目的端口 10 = 3200 点
        s_lo, s_hi = 0x0A000000, 0x0A000003
        d_lo, d_hi = 0xC0A80000, 0xC0A80003
        r1 = B(proto=(0, 0), src=(s_lo, s_hi), dst=(d_lo, d_hi),
               sport=(2, 7), dport=(0, 9))
        r2 = B(proto=(0, 1), src=(s_lo, s_hi), dst=(d_lo, d_hi),
               sport=(0, 9), dport=(3, 5))
        r3 = B(proto=(1, 1), src=(s_lo + 1, s_hi), dst=(d_lo, d_hi),
               sport=(0, 4), dport=(0, 9))

        union = BoxList.empty()
        for b, owner in ((r1, "R1"), (r2, "R2"), (r3, "R3")):
            union.add(b, owner)
        self.assertTrue(pairwise_disjoint(union.boxes))

        points = list(itertools.product(
            range(2), range(s_lo, s_hi + 1), range(d_lo, d_hi + 1),
            range(10), range(10)))
        for p in points:
            expected = set()
            for b, owner in ((r1, "R1"), (r2, "R2"), (r3, "R3")):
                if in_bounds(p, b):
                    expected.add(owner)
            hit = [bx for bx in union.boxes if in_bounds(p, bx.bounds)]
            if expected:
                self.assertEqual(len(hit), 1, f"点 {p} 应恰在一个盒子中")
                self.assertEqual(set(hit[0].owners), expected, f"点 {p} 属主错误")
            else:
                self.assertEqual(hit, [], f"点 {p} 不应被覆盖")

    def test_covering_owners_full_vs_partial(self):
        union = BoxList.empty()
        union.add(B(proto=(0, 0)), "TCP-ALL")
        union.add(B(proto=(1, 1)), "UDP-ALL")
        owners = union.covering_owners(
            B(proto=(0, 1), src=(10, 20), dst=(30, 40), sport=(1, 2), dport=(3, 4)))
        self.assertEqual(owners, {"TCP-ALL", "UDP-ALL"})

        # 只覆盖 TCP 部分，整个 BOTH 区域不算被覆盖
        only_tcp = BoxList.empty()
        only_tcp.add(B(proto=(0, 0)), "TCP-ALL")
        self.assertEqual(
            only_tcp.covering_owners(B(proto=(0, 1), sport=(1, 1), dport=(1, 1))),
            set())

    def test_cidr_string_overlap_is_not_enough(self):
        """10.0.0.0/8 与 11.0.0.0/8 字符串相似但地址区域不相交，不得误判覆盖。"""
        union = BoxList.empty()
        union.add(B(proto=(0, 1), src=(0x0A000000, 0x0AFFFFFF)), "R1")
        target = B(proto=(0, 1), src=(0x0B000000, 0x0BFFFFFF))
        self.assertEqual(union.covering_owners(target), set())
        union.add(target, "R2")
        self.assertEqual(union.covering_owners(target), {"R2"})


def make_rule(rid, idx, protos, src, dst, sport, dport):
    def cidr_bounds(cidr):
        import ipaddress
        net = ipaddress.IPv4Network(cidr, strict=True)
        return int(net.network_address), int(net.broadcast_address)

    sl, sh = cidr_bounds(src)
    dl, dh = cidr_bounds(dst)
    return Rule(rid, idx, tuple(protos), src, dst, sl, sh, dl, dh,
                sport[0], sport[1], dport[0], dport[1])


class AdjudicationTests(unittest.TestCase):
    def test_first_rule_always_has_witness(self):
        rules = [make_rule("R1", 0, ("TCP", "UDP"), "0.0.0.0/0", "0.0.0.0/0",
                           (0, 65535), (0, 65535))]
        out = adjudicate(rules)
        self.assertEqual(out[0]["verdict"], "PARTIALLY_COVERED")
        self.assertEqual(out[0]["witness"], {
            "protocol": "TCP", "src_addr": "0.0.0.0", "dst_addr": "0.0.0.0",
            "src_port": 0, "dst_port": 0})

    def test_partial_cover_witness_is_sorted_minimum(self):
        rules = [
            make_rule("R1", 0, ("TCP",), "10.0.0.0/8", "0.0.0.0/0",
                      (0, 65535), (0, 65535)),
            make_rule("R2", 1, ("TCP", "UDP"), "0.0.0.0/0", "0.0.0.0/0",
                      (0, 65535), (0, 65535)),
        ]
        out = adjudicate(rules)
        self.assertEqual(out[0]["verdict"], "PARTIALLY_COVERED")
        self.assertEqual(out[1]["verdict"], "PARTIALLY_COVERED")
        # 剩余区域 = UDP 全域 ∪ {TCP, 源∉10/8}；排序最小点取 TCP 的 0.0.0.0
        self.assertEqual(out[1]["witness"]["protocol"], "TCP")
        self.assertEqual(out[1]["witness"]["src_addr"], "0.0.0.0")
        self.assertEqual(out[1]["witness"]["src_port"], 0)

    def test_full_cover_single_and_multiple_owners(self):
        rules = [
            make_rule("BIG", 0, ("TCP", "UDP"), "0.0.0.0/0", "0.0.0.0/0",
                      (0, 65535), (0, 65535)),
            make_rule("NARROW", 1, ("TCP",), "10.0.0.0/8", "192.168.0.0/16",
                      (1000, 2000), (443, 443)),
        ]
        out = adjudicate(rules)
        self.assertEqual(out[1]["verdict"], "FULLY_COVERED")
        self.assertEqual(out[1]["covered_by"], ["BIG"])
        self.assertIsNone(out[1]["witness"])

        rules2 = [
            make_rule("T", 0, ("TCP",), "0.0.0.0/0", "0.0.0.0/0",
                      (0, 65535), (0, 65535)),
            make_rule("U", 1, ("UDP",), "0.0.0.0/0", "0.0.0.0/0",
                      (0, 65535), (0, 65535)),
            make_rule("M", 2, ("TCP", "UDP"), "10.0.0.0/8", "10.0.0.0/8",
                      (0, 65535), (0, 65535)),
        ]
        out2 = adjudicate(rules2)
        self.assertEqual(out2[2]["verdict"], "FULLY_COVERED")
        self.assertEqual(out2[2]["covered_by"], ["T", "U"])

    def test_port_corners_partial_vs_full(self):
        base = dict(src="0.0.0.0/0", dst="0.0.0.0/0")
        rules = [
            make_rule("R1", 0, ("TCP",), sport=(100, 200), dport=(100, 200), **base),
            make_rule("R2", 1, ("TCP",), sport=(150, 200), dport=(100, 200), **base),
            make_rule("R3", 2, ("TCP",), sport=(100, 200), dport=(150, 200), **base),
        ]
        out = adjudicate(rules)
        # R2 源端口完全落在 R1 内、目的端口相同 → 完全遮蔽
        self.assertEqual(out[1]["verdict"], "FULLY_COVERED")
        # R3 的 dport=[150,200] 同样是 R1 dport=[100,200] 的子集 → 完全遮蔽
        self.assertEqual(out[2]["verdict"], "FULLY_COVERED")

        # dport 扩到 [150,250]，201..250 为剩余区域
        rules[2] = make_rule("R3", 2, ("TCP",), sport=(100, 200),
                             dport=(150, 250), **base)
        out = adjudicate(rules)
        self.assertEqual(out[2]["verdict"], "PARTIALLY_COVERED")
        self.assertEqual(out[2]["witness"]["dst_port"], 201)
        self.assertEqual(out[2]["witness"]["src_port"], 100)


class ValidationTests(unittest.TestCase):
    def _payload(self, **over):
        p = {
            "audit_id": "a-1",
            "rules": [{
                "rule_id": "R1", "protocol": "BOTH",
                "src_cidr": "10.0.0.0/24", "dst_cidr": "0.0.0.0/0",
                "src_port": [0, 65535], "dst_port": [0, 65535],
            }],
        }
        p.update(over)
        return p

    def test_bad_cidr_host_bits(self):
        p = self._payload()
        p["rules"][0]["src_cidr"] = "10.0.0.1/24"
        with self.assertRaises(ValueError):
            parse_audit(p)

    def test_bad_cidr_and_mask(self):
        for bad in ("10.0.0.0/33", "999.0.0.0/8", "10.0.0.0", "not-cidr", "::1/128"):
            p = self._payload()
            p["rules"][0]["src_cidr"] = bad
            with self.assertRaises(ValueError, msg=bad):
                parse_audit(p)

    def test_bad_port_range(self):
        for bad in ([-1, 10], [0, 70000], [500, 499]):
            p = self._payload()
            p["rules"][0]["src_port"] = bad
            with self.assertRaises(ValueError, msg=str(bad)):
                parse_audit(p)

    def test_duplicate_rule_id(self):
        p = self._payload()
        p["rules"].append(dict(p["rules"][0]))
        with self.assertRaises(ValueError):
            parse_audit(p)

    def test_rule_count_limit(self):
        p = self._payload()
        p["rules"] = []
        for i in range(19):
            r = dict(p["rules"][0]) if p["rules"] else {
                "rule_id": f"R{i}", "protocol": "TCP",
                "src_cidr": "0.0.0.0/0", "dst_cidr": "0.0.0.0/0",
                "src_port": [0, 65535], "dst_port": [0, 65535]}
            r["rule_id"] = f"R{i}"
            p["rules"].append(r)
        with self.assertRaises(ValueError):
            parse_audit(p)

    def test_bad_audit_id(self):
        for bad in ("", "x" * 200, "bad id", 12345):
            with self.assertRaises(ValueError, msg=str(bad)):
                parse_audit(self._payload(audit_id=bad))


if __name__ == "__main__":
    unittest.main()
