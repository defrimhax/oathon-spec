"""UUIDv7 and protocol-timestamp helpers.

Implemented locally (not via uuid.uuid7) to stay Python 3.12-compatible and
to allow injectable clocks for deterministic tests.
"""

from __future__ import annotations

import datetime as _dt
import os
import time


def now_ns() -> int:
    return time.time_ns()


def uuid7(ts_ns: int | None = None) -> str:
    """RFC 9562 UUIDv7: 48-bit unix ms, version 7, variant 10, random tail."""
    if ts_ns is None:
        ts_ns = now_ns()
    ts_ms = ts_ns // 1_000_000
    rand = os.urandom(10)
    rand_a = int.from_bytes(rand[:2]) & 0x0FFF
    rand_b = int.from_bytes(rand[2:]) & 0x3FFFFFFFFFFFFFFF
    value = (ts_ms & 0xFFFFFFFFFFFF) << 80
    value |= 0x7 << 76
    value |= rand_a << 64
    value |= 0b10 << 62
    value |= rand_b
    hexstr = f"{value:032x}"
    return f"{hexstr[0:8]}-{hexstr[8:12]}-{hexstr[12:16]}-{hexstr[16:20]}-{hexstr[20:32]}"


def protocol_timestamp(ts_ns: int | None = None) -> str:
    """CRYPTO-006 format: YYYY-MM-DDTHH:MM:SS.sssZ (UTC, millisecond)."""
    if ts_ns is None:
        ts_ns = now_ns()
    ms = ts_ns // 1_000_000
    dt = _dt.datetime.fromtimestamp(ms / 1000.0, tz=_dt.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"


def utc_day(timestamp: str) -> str:
    """The UTC calendar day of a protocol timestamp (for SEGMENT-005)."""
    return timestamp[:10]
