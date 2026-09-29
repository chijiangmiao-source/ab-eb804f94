"""五维区域（协议 × 源IPv4 × 目的IPv4 × 源端口 × 目的端口）的
不相交盒子（Cartesian 积）集合代数。

关键性质：
* 所有坐标均为闭区间整数域；协议维为离散集合（TCP=0/UDP=1）。
* BoxList 始终维护互不相交的盒子，每个盒子记录覆盖它的规则标识集合。
* subtract 用逐维“切前/切中/切后”的方式做差集，盒子数量有上界，
  既不抽样地址、也不枚举端口。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple

PROTOCOLS = ("TCP", "UDP")

# 盒子在协议/源地址/目的地址/源端口/目的端口五维上的闭区间
Bounds = Tuple[Tuple[int, int], ...]  # 长度恰为 5


@dataclass(frozen=True)
class Box:
    """五维闭区间笛卡尔积，owners 为覆盖该盒子全部点的规则标识集合。"""

    bounds: Bounds
    owners: frozenset

    def min_point(self) -> Tuple[int, int, int, int, int]:
        """该盒子按排序意义下的最小报文点（每维都取左端点）。"""
        return tuple(self.bounds[d][0] for d in range(5))  # type: ignore[return-value]


def _clip(lo: int, hi: int, lo2: int, hi2: int) -> Tuple[int, int] | None:
    nlo, nhi = max(lo, lo2), min(hi, hi2)
    return (nlo, nhi) if nlo <= nhi else None


def _intersect(bounds: Bounds, other: Bounds) -> List[Tuple[int, int]] | None:
    pieces: List[Tuple[int, int]] = []
    for d in range(5):
        part = _clip(*bounds[d], *other[d])
        if part is None:
            return None
        pieces.append(part)
    return pieces


@dataclass
class BoxList:
    """互不相交盒子的集合；每个盒子携带覆盖其全部点的规则标识。"""

    boxes: List[Box]

    @classmethod
    def empty(cls) -> "BoxList":
        return cls([])

    def _fragments_outside(self, cut: Bounds) -> List[Box]:
        """所有盒子被 cut 切开后，落在 cut 之外的分片。"""
        out: List[Box] = []
        for box in self.boxes:
            if _intersect(box.bounds, cut) is None:
                out.append(box)  # 完全不相交，整盒保留
            else:
                out.extend(_subtract_box(box, cut))
        return out

    def subtract(self, bounds: Bounds) -> None:
        """原地从所有盒子中挖去 bounds 区域。"""
        self.boxes = self._fragments_outside(bounds)

    def add(self, bounds: Bounds, owner: str) -> None:
        """把 bounds 并入并集；重叠分片的属主集合取并集。"""
        originals = self.boxes

        # 1. 既有盒子：bounds 之外的分片不变，交集分片追加新属主
        merged: List[Box] = []
        for box in originals:
            inter = _intersect(box.bounds, bounds)
            if inter is None:
                merged.append(box)
                continue
            merged.extend(_subtract_box(box, bounds))
            merged.append(Box(tuple(inter), box.owners | {owner}))

        # 2. bounds 中此前未被任何规则覆盖的部分，仅归新规则所有
        fresh = BoxList([Box(bounds, frozenset({owner}))])
        for box in originals:
            fresh.subtract(box.bounds)

        self.boxes = merged + fresh.boxes

    def covering_owners(self, bounds: Bounds) -> set:
        """若 bounds 被本并集完全覆盖，返回参与覆盖的规则标识并集；否则空集。"""
        remaining = BoxList([Box(bounds, frozenset())])
        owners: set = set()
        for box in self.boxes:
            if not remaining.boxes:
                break
            if _intersect(box.bounds, bounds) is not None:
                owners |= box.owners
                remaining.subtract(box.bounds)
        return owners if not remaining.boxes else set()


def _subtract_box(box: Box, cut: Bounds) -> List[Box]:
    """从单个盒子中挖去 cut，返回落在 cut 之外的分片（至多 3^5-1 个）。"""
    parts: List[List[Tuple[int, int]]] = [[] for _ in range(5)]
    for d in range(5):
        lo, hi = box.bounds[d]
        clo, chi = cut[d]
        if clo > lo:
            parts[d].append((lo, min(hi, clo - 1)))
        nlo, nhi = max(lo, clo), min(hi, chi)
        if nlo <= nhi:
            parts[d].append((nlo, nhi))
        if chi < hi:
            parts[d].append((max(lo, chi + 1), hi))

    result: List[Box] = []
    for p0 in parts[0]:
        for p1 in parts[1]:
            for p2 in parts[2]:
                for p3 in parts[3]:
                    for p4 in parts[4]:
                        piece = (p0, p1, p2, p3, p4)
                        inside_cut = all(
                            piece[d][0] >= cut[d][0] and piece[d][1] <= cut[d][1]
                            for d in range(5)
                        )
                        if not inside_cut:
                            result.append(Box(piece, box.owners))
    return result


def bounds_from_rule(
    protos: Sequence[str],
    src_lo: int,
    src_hi: int,
    dst_lo: int,
    dst_hi: int,
    sport_lo: int,
    sport_hi: int,
    dport_lo: int,
    dport_hi: int,
) -> Bounds:
    pset = set(protos)
    if pset == {"TCP", "UDP"}:
        proto = (0, 1)
    elif pset == {"TCP"}:
        proto = (0, 0)
    else:
        proto = (1, 1)
    return (
        proto,
        (src_lo, src_hi),
        (dst_lo, dst_hi),
        (sport_lo, sport_hi),
        (dport_lo, dport_hi),
    )
