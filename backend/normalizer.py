"""Normalize real Gigahorse/DYELS Datalog outputs into ABI NEXUS v2 storage IR.

No invented types: absent/incompatible Datalog fields are preserved as unknown.
The relations use actual names from clientlib/storage_modeling/storage_modeling_api.dl.
"""
from __future__ import annotations

import csv
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

RELATIONS = (
    "StorageVariableInfo",
    "StorageVariable_Type",
    "DataStructure_Type",
    "Mapping_KeyType",
    "DataStructure_ValueOrElementType",
    "DataStructureValueIsStruct",
    "StorageStmtKindAndConstruct",
    "StorageStmt_HighLevelUses",
)
MAX_ROWS = 10000
MAX_BYTES_PER_RELATION = 4_000_000
CONST = re.compile(r"(?:\$)?Constant\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)", re.IGNORECASE)
PACKED = re.compile(r"(?:\$)?TightlyPackedVariable\s*\(.*?,\s*(\d+)\s*,\s*(\d+)\s*\)", re.IGNORECASE)
HEX = re.compile(r"0x[0-9a-fA-F]+")
MAPPING = re.compile(r"(?:\$)?Mapping\s*\(", re.IGNORECASE)


def read_relations(folder: Path) -> dict[str, list[list[str]]]:
    """CSV extension here is Souffle's TSV output, not comma-separated text."""
    records: dict[str, list[list[str]]] = {}
    for name in RELATIONS:
        filename = folder / f"{name}.csv"
        if not filename.is_file():
            continue
        if filename.stat().st_size > MAX_BYTES_PER_RELATION:
            raise ValueError(f"DYELS relation too large: {name}")
        with filename.open("r", encoding="utf-8", errors="replace", newline="") as fp:
            rows = []
            for i, row in enumerate(csv.reader(fp, delimiter="\t")):
                if i >= MAX_ROWS:
                    raise ValueError(f"DYELS relation exceeds {MAX_ROWS} rows: {name}")
                if row:
                    rows.append([field.strip()[:8192] for field in row])
        records[name] = rows
    return records


def _root(construct: str) -> str | None:
    match = CONST.search(construct)
    if match:
        return hex(int(match.group(1), 0))
    # StorageVariableInfo sometimes gives the slot itself or storage symbol.
    candidate = construct.strip()
    if re.fullmatch(r"(?:0x[0-9a-fA-F]+|\d+)", candidate):
        return hex(int(candidate, 0))
    match = re.search(r"(?:stor|slot)(0x[0-9a-fA-F]+)", candidate)
    return hex(int(match.group(1), 0)) if match else None


def _loc(label: str) -> str:
    if "transient" in label.lower() or "tstor" in label.lower():
        return "transient"
    return "persistent"


def _num(text: str) -> int | None:
    try:
        value = int(text, 0) if str(text).lower().startswith("0x") else int(text)
        return value if 0 <= value <= 4096 else None
    except (TypeError, ValueError):
        return None


def _packed(construct: str) -> tuple[int, int] | None:
    match = PACKED.search(construct)
    if not match:
        return None
    lo, hi = int(match.group(1)), int(match.group(2))
    return (lo, hi) if 0 <= lo <= hi < 32 else None


def normalize(relations: dict[str, list[list[str]]], byte_count: int) -> dict[str, Any]:
    slots: dict[tuple[str, str], dict[str, Any]] = {}
    mappings: dict[tuple[str, int, str], dict[str, Any]] = {}
    warnings: list[str] = []

    def slot_at(location: str, slot: str) -> dict[str, Any]:
        key = (location, slot)
        if key not in slots:
            slots[key] = {"slot": slot, "location": location, "fields": [], "accesses": []}
        return slots[key]

    def field_at(s: dict[str, Any], off: int, width: int, type_hint: str,
                 evidence: str, name: str = "") -> None:
        if not (0 <= off < 32 and 1 <= width <= 32 - off):
            return
        for old in s["fields"]:
            if old["offset"] == off and old["width"] == width:
                if type_hint != "unknown" and old.get("type") in ("unknown", None):
                    old["type"] = type_hint
                if evidence not in old["evidence"]:
                    old["evidence"].append(evidence)
                return
        s["fields"].append({
            "offset": off, "width": width, "name": name,
            "type": type_hint or "unknown", "confidence": "dyels-datalog",
            "evidence": [evidence],
        })

    def mapping_at(loc: str, cons: str, evidence: str) -> dict[str, Any] | None:
        root = _root(cons)
        depth = len(MAPPING.findall(cons))
        if root is None or depth == 0:
            return None
        key = (root, depth, loc)
        if key not in mappings:
            mappings[key] = {
                "slot": root, "location": loc, "depth": depth,
                "keys": [{"type": "unknown"} for _ in range(depth)],
                "valueType": "unknown", "confidence": "dyels-datalog",
                "evidence": [], "accesses": [], "construct": cons[:4000],
            }
        m = mappings[key]
        if evidence not in m["evidence"]:
            m["evidence"].append(evidence)
        slot_at(loc, root)
        return m

    # Exact high-level variable metadata: column layout defined by StorageVariableInfo.
    for row in relations.get("StorageVariableInfo", []):
        if len(row) < 5:
            continue
        variable, location, stor_slot, low_s, high_s = row[:5]
        root, low, high = _root(stor_slot) or _root(variable), _num(low_s), _num(high_s)
        if root is None or low is None or high is None or high < low or high >= 32:
            continue
        field_at(slot_at(_loc(location), root), low, high-low+1,
                 "unknown", "StorageVariableInfo", name=variable)

    # Type relation models top-level values and packed slices of storage words.
    for row in relations.get("StorageVariable_Type", []):
        if len(row) < 3:
            continue
        location, construct, dtype = row[:3]
        root = _root(construct)
        if root is None:
            continue
        loc = _loc(location)
        s = slot_at(loc, root)
        packed = _packed(construct)
        if packed:
            lo, hi = packed
            field_at(s, lo, hi-lo+1, dtype, "StorageVariable_Type")
        elif len(MAPPING.findall(construct)) == 0 and "Array(" not in construct:
            if len(s["fields"]) == 1:
                f = s["fields"][0]
                if f["type"] == "unknown":
                    f["type"] = dtype
                    f["evidence"].append("StorageVariable_Type")
            elif not s["fields"]:
                # No range proof: keep as a type candidate, don't assert a 32-byte field.
                s.setdefault("typeCandidates", []).append({
                    "type": dtype, "evidence": "StorageVariable_Type",
                    "range": "unknown"
                })
        mapping_at(loc, construct, "StorageVariable_Type")

    # Mapping_KeyType contains type at each nested mapping construct.
    for row in relations.get("Mapping_KeyType", []):
        if len(row) < 3:
            continue
        location, construct, dtype = row[:3]
        m = mapping_at(_loc(location), construct, "Mapping_KeyType")
        if not m:
            continue
        level = m["depth"] - 1
        m["keys"][level] = {"type": dtype, "evidence": "Mapping_KeyType"}

    for row in relations.get("DataStructure_ValueOrElementType", []):
        if len(row) < 3:
            continue
        location, construct, dtype = row[:3]
        m = mapping_at(_loc(location), construct, "DataStructure_ValueOrElementType")
        if m:
            m["valueType"] = dtype
    for row in relations.get("DataStructure_Type", []):
        if len(row) < 3:
            continue
        location, construct, dtype = row[:3]
        mapping_at(_loc(location), construct, "DataStructure_Type")

    for row in relations.get("StorageStmtKindAndConstruct", []):
        if len(row) < 4:
            continue
        stmt, kind, location, construct = row[:4]
        root = _root(construct)
        if root is None:
            continue
        loc = _loc(location)
        access = {"operation": kind[:150], "stmt": stmt[:150]}
        s = slot_at(loc, root)
        if len(s["accesses"]) < 50 and access not in s["accesses"]:
            s["accesses"].append(access)
        m = mapping_at(loc, construct, "StorageStmtKindAndConstruct")
        if m and len(m["accesses"]) < 50:
            m["accesses"].append(access)

    # Key type information from different levels may be spread over constructs
    # Mapping(Constant(p)), Mapping(Mapping(Constant(p))) etc.
    for m in mappings.values():
        for lower in range(1, m["depth"]):
            ancestor = mappings.get((m["slot"], lower, m["location"]))
            if ancestor and ancestor["keys"][lower-1]["type"] != "unknown":
                m["keys"][lower-1] = dict(ancestor["keys"][lower-1])

    for s in slots.values():
        ranges = sorted(s["fields"], key=lambda f: (f["offset"], f["width"]))
        if any(b["offset"] < a["offset"]+a["width"] for a,b in zip(ranges, ranges[1:])):
            s["overlapObserved"] = True
            warnings.append("Có vùng byte chồng lấn ở "+s["slot"]+
                            "; chưa đủ cơ sở kết luận storage collision.")
        else:
            s["overlapObserved"] = False

    if not relations:
        warnings.append("Không có quan hệ DYELS nào được xuất từ analyzer.")
    if not relations.get("Mapping_KeyType"):
        warnings.append("Mapping_KeyType không có hàng kết quả; key types chưa thể xác minh.")
    if not relations.get("StorageVariableInfo"):
        warnings.append("StorageVariableInfo không có hàng kết quả; packed offsets có thể thiếu.")
    ordered_slots = sorted(slots.values(), key=lambda x:(x["location"],int(x["slot"],16)))
    ordered_maps = sorted(mappings.values(),key=lambda x:(x["location"],int(x["slot"],16),x["depth"]))
    return {
        "engine":"gigahorse-dyels", "status":"completed",
        "backendVerified":True, "bytes":byte_count,
        "slots":ordered_slots[:150], "mappings":ordered_maps[:100],
        "warnings":warnings,
        "relations":{name: rows[:30] for name,rows in relations.items()},
        "relationCounts":{name:len(rows) for name,rows in relations.items()},
        "disclaimer":"Evidence from DYELS Datalog, not original Solidity source or a security proof.",
    }
