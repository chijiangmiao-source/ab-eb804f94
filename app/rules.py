"""规则解析、校验与按优先顺序的遮蔽裁决。"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from .geometry import Box, BoxList, PROTOCOLS, bounds_from_rule

MAX_RULES = 18
_AUDIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_RULE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_PROTO_ALIASES = {
    "TCP": ("TCP",),
    "UDP": ("UDP",),
    "BOTH": ("TCP", "UDP"),
}


class ValidationError(ValueError):
    """载荷非法（CIDR、端口、标识等），必须拒绝且不落盘。"""


@dataclass(frozen=True)
class Rule:
    rule_id: str
    index: int
    protos: Tuple[str, ...]
    src_cidr: str
    dst_cidr: str
    src_lo: int
    src_hi: int
    dst_lo: int
    dst_hi: int
    sport_lo: int
    sport_hi: int
    dport_lo: int
    dport_hi: int

    def bounds(self):
        return bounds_from_rule(
            self.protos,
            self.src_lo, self.src_hi,
            self.dst_lo, self.dst_hi,
            self.sport_lo, self.sport_hi,
            self.dport_lo, self.dport_hi,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "protocol": _proto_repr(self.protos),
            "src_cidr": self.src_cidr,
            "dst_cidr": self.dst_cidr,
            "src_port": [self.sport_lo, self.sport_hi],
            "dst_port": [self.dport_lo, self.dport_hi],
        }


def _proto_repr(protos: Tuple[str, ...]) -> str:
    return "BOTH" if len(protos) == 2 else protos[0]


def _parse_cidr(value: Any, field_name: str) -> Tuple[str, int, int]:
    """严格 CIDR 校验：拒绝主机位非零、非法地址、非法掩码。"""
    if not isinstance(value, str) or value.count("/") != 1:
        raise ValidationError(f"{field_name} 必须是形如 a.b.c.d/n 的 IPv4 CIDR")
    addr, _, mask = value.partition("/")
    if not re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", addr) or not mask.isdigit():
        raise ValidationError(f"{field_name} 不是合法 IPv4 CIDR: {value!r}")
    try:
        net = ipaddress.IPv4Network(value, strict=True)
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise ValidationError(f"{field_name} 不是合法 IPv4 CIDR（{exc}）") from None
    if not 0 <= int(mask) <= 32:
        raise ValidationError(f"{field_name} 掩码长度越界: {value!r}")
    return str(net), int(net.network_address), int(net.broadcast_address)


def _parse_port(value: Any, field_name: str) -> Tuple[int, int]:
    """闭区间端口 [lo, hi]，0..65535。"""
    if isinstance(value, dict):
        lo, hi = value.get("start", value.get("lo")), value.get("end", value.get("hi"))
    elif isinstance(value, (list, tuple)) and len(value) == 2:
        lo, hi = value
    else:
        raise ValidationError(f"{field_name} 必须是含两个整数的闭区间 [起, 止]")
    if isinstance(lo, bool) or isinstance(hi, bool) or not isinstance(lo, int) or not isinstance(hi, int):
        raise ValidationError(f"{field_name} 必须是整数闭区间")
    if not (0 <= lo <= 65535 and 0 <= hi <= 65535):
        raise ValidationError(f"{field_name} 端口必须落在 0..65535: [{lo}, {hi}]")
    if lo > hi:
        raise ValidationError(f"{field_name} 区间起点不得大于止点: [{lo}, {hi}]")
    return lo, hi


def parse_audit(payload: Any) -> Tuple[str, List[Rule]]:
    """解析并校验整份提交，返回 (audit_id, 按优先顺序排列的规则)。"""
    if not isinstance(payload, dict):
        raise ValidationError("请求体必须是 JSON 对象")

    audit_id = payload.get("audit_id")
    if not isinstance(audit_id, str) or not _AUDIT_RE.fullmatch(audit_id.strip()):
        raise ValidationError("audit_id 必须为 1..128 位字母数字及 ._- 组成的非空标识")
    audit_id = audit_id.strip()

    raw_rules = payload.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ValidationError("rules 必须为非空数组")
    if len(raw_rules) > MAX_RULES:
        raise ValidationError(f"每个审计标识至多提交 {MAX_RULES} 条规则")

    rules: List[Rule] = []
    seen_ids = set()
    for i, raw in enumerate(raw_rules):
        where = f"第 {i + 1} 条规则"
        if not isinstance(raw, dict):
            raise ValidationError(f"{where} 必须是 JSON 对象")
        rid = raw.get("rule_id")
        if not isinstance(rid, str) or not _RULE_RE.fullmatch(rid.strip()):
            raise ValidationError(f"{where} 的 rule_id 必须为 1..64 位字母数字及 ._- 组成")
        rid = rid.strip()
        if rid in seen_ids:
            raise ValidationError(f"规则标识重复: {rid!r}")
        seen_ids.add(rid)

        proto = raw.get("protocol", "BOTH")
        if not isinstance(proto, str) or proto not in _PROTO_ALIASES:
            raise ValidationError(f"{where} 的 protocol 只能是 TCP / UDP / BOTH")
        protos = _PROTO_ALIASES[proto]

        src_cidr, src_lo, src_hi = _parse_cidr(raw.get("src_cidr"), f"{where} 源 CIDR")
        dst_cidr, dst_lo, dst_hi = _parse_cidr(raw.get("dst_cidr"), f"{where} 目的 CIDR")
        sport_lo, sport_hi = _parse_port(raw.get("src_port"), f"{where} 源端口")
        dport_lo, dport_hi = _parse_port(raw.get("dst_port"), f"{where} 目的端口")

        rules.append(Rule(
            rule_id=rid, index=i, protos=protos,
            src_cidr=src_cidr, dst_cidr=dst_cidr,
            src_lo=src_lo, src_hi=src_hi, dst_lo=dst_lo, dst_hi=dst_hi,
            sport_lo=sport_lo, sport_hi=sport_hi,
            dport_lo=dport_lo, dport_hi=dport_hi,
        ))
    return audit_id, rules


def _ip(n: int) -> str:
    return str(ipaddress.IPv4Address(n))


def _witness(point: Tuple[int, int, int, int, int]) -> Dict[str, Any]:
    proto, src, dst, sport, dport = point
    return {
        "protocol": PROTOCOLS[proto],
        "src_addr": _ip(src),
        "dst_addr": _ip(dst),
        "src_port": sport,
        "dst_port": dport,
    }


def adjudicate(rules: List[Rule]) -> List[Dict[str, Any]]:
    """按提交顺序逐条裁决：剩余区域非空则给最小见证，否则给覆盖者集合。"""
    union = BoxList.empty()
    results: List[Dict[str, Any]] = []

    for rule in rules:
        bounds = rule.bounds()
        owners = union.covering_owners(bounds)

        if owners:
            results.append({
                "rule_id": rule.rule_id,
                "index": rule.index,
                "verdict": "FULLY_COVERED",
                "covered_by": sorted(owners),
                "witness": None,
            })
        else:
            remaining = BoxList([Box(bounds, frozenset())])
            for box in union.boxes:
                remaining.subtract(box.bounds)
            points = sorted(box.min_point() for box in remaining.boxes)
            results.append({
                "rule_id": rule.rule_id,
                "index": rule.index,
                "verdict": "PARTIALLY_COVERED",
                "covered_by": [],
                "witness": _witness(points[0]),
            })

        union.add(bounds, rule.rule_id)

    return results


def fingerprint(audit_id: str, rules: List[Rule]) -> str:
    """规范化载荷指纹：同标识重传必须逐字节等价才算幂等。"""
    import hashlib
    import json

    canonical = json.dumps(
        {"audit_id": audit_id, "rules": [r.to_dict() for r in rules]},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
