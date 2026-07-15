#!/usr/bin/env python3
"""Extraction-free manual event inspector for ABCurves Capture v0.4.1 ZIPs.

Open a ``session_..._SEND_THIS.zip`` with the button, pass it on the command
line, or drag it onto the window on Windows.  The viewer validates the fixed
data-only container and the hashes of every artifact it reads.  It never
extracts files, executes submitted content, decodes arbitrary markup, or shows
raw USB payload bytes.

This is a manual QA aid, not a replacement for the private pool validator.
"""

from __future__ import annotations

import argparse
import bisect
import ctypes
import hashlib
import json
import math
import os
import re
import stat
import struct
import sys
import threading
import time
import zlib
from array import array
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterable, Iterator, Sequence

import tkinter as tk
from tkinter import filedialog, messagebox, ttk


APP_TITLE = "ABCurves Capture Session Inspector"
SESSION_SCHEMA = "abcurves.capture.session.v2"
COMPLETE_SCHEMA = "abcurves.capture.complete.v2"
EVENT_SCHEMA = "abcurves.gameplay.trainer_event.v2"
RAW_SCHEMA = "abcurves.gameplay.raw_input_witness.v1"
PROTOCOL_ID = "abcurves.capture-trainer.protocol-v3"
PROTOCOL_SHA256 = "7b93cca3ba152f4c9c3ccf4a759ae02173e65750d552f8f71a06ef54a7a8bcf5"
RELEASE_VERSION = "0.4.1"
RELEASE_REVISION = "e3896d94b3d76ceaa83d5df0265c050f99c5ad38"

SESSION_ID_RE = re.compile(r"s-[0-9a-f]{32}\Z")
HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
CRC_PREFIX_RE = re.compile(br'^\{"_crc32":"([0-9a-f]{8})",')

CONTROL_ARTIFACTS = {"COMPLETE", "checksums.sha256"}
DATA_ARTIFACTS = {
    "manifest.json",
    "capture/capture_anomalies.jsonl",
    "capture/hid_report_descriptor.bin",
    "capture/mouse_reports.abcr2",
    "capture/mouse_usb.pcap",
    "clocks/anchors.jsonl",
    "gameplay/blocks.jsonl",
    "gameplay/events.jsonl",
    "gameplay/focus.jsonl",
    "gameplay/lifecycle.jsonl",
    "gameplay/pauses.jsonl",
    "gameplay/presentation.jsonl",
    "gameplay/raw_input_witness.jsonl",
}
ARTIFACT_MAX_EXPANDED = {
    "manifest.json": 16 << 20,
    # A valid release session can contain a large anomaly journal when a HID
    # interface repeatedly emits an unsupported report ID. Keep this below the
    # archive/member limits while allowing the collector's released output.
    "capture/capture_anomalies.jsonl": 256 << 20,
    "capture/hid_report_descriptor.bin": 1 << 20,
    "capture/mouse_reports.abcr2": 256 << 20,
    "capture/mouse_usb.pcap": 384 << 20,
    "clocks/anchors.jsonl": 64 << 20,
    "gameplay/blocks.jsonl": 64 << 20,
    "gameplay/events.jsonl": 64 << 20,
    "gameplay/focus.jsonl": 64 << 20,
    "gameplay/lifecycle.jsonl": 64 << 20,
    "gameplay/pauses.jsonl": 64 << 20,
    "gameplay/presentation.jsonl": 64 << 20,
    "gameplay/raw_input_witness.jsonl": 640 << 20,
    "COMPLETE": 16 << 20,
    "checksums.sha256": 16 << 20,
}

REVIEW_LABELS = (
    "looks_good",
    "weird_but_valid_human",
    "suspicious_timing",
    "suspicious_path",
    "suspicious_integration",
    "exclude_recommended",
    "needs_followup",
)


class LoadError(RuntimeError):
    pass


def reject(message: str) -> None:
    raise LoadError(message)


def strict_json(data: bytes, label: str, maximum: int = 4 << 20) -> Any:
    if not data or len(data) > maximum or b"\x00" in data or data.startswith(b"\xef\xbb\xbf"):
        reject(f"{label}: unsafe JSON size/encoding")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key}")
            result[key] = value
        return result

    try:
        return json.loads(
            data.decode("utf-8", "strict"),
            object_pairs_hook=no_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        reject(f"{label}: invalid strict JSON ({error})")


def finite_number(value: Any, label: str, minimum: float = -1.0e12, maximum: float = 1.0e12) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        reject(f"{label} is not a finite number")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        reject(f"{label} is outside safe bounds")
    return result


def bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        reject(f"{label} is not a bounded integer")
    return int(value)


@dataclass(slots=True)
class Member:
    name: str
    relative: str
    crc32: int
    compressed: int
    expanded: int
    method: int
    local_offset: int
    data_offset: int = 0


class SafeArchive:
    """Small reader for the exact canonical ZIP32 emitted by Capture v0.4.1."""

    EOCD = struct.Struct("<IHHHHIIH")
    CENTRAL = struct.Struct("<IHHHHHHIIIHHHHHII")
    LOCAL = struct.Struct("<IHHHHHIIIHH")
    MAX_ARCHIVE = 256 << 20
    MAX_EXPANDED = 1 << 30
    MAX_MEMBER = 768 << 20
    MAX_RATIO = 50.0
    CHUNK = 64 << 10

    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle: BinaryIO | None = None
        self.size = 0
        self.initial_stat: os.stat_result | None = None
        self.members: list[Member] = []
        self.by_relative: dict[str, Member] = {}
        self.session_id = ""
        self.expected_hashes: dict[str, str] = {}

    def __enter__(self) -> "SafeArchive":
        try:
            info = os.lstat(self.path)
        except OSError as error:
            reject(f"Cannot stat submission: {error}")
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            reject("Submission is not a regular non-link file")
        if getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            reject("Submission is a Windows reparse point")
        if info.st_size < self.EOCD.size or info.st_size > self.MAX_ARCHIVE:
            reject("Archive byte size is outside the inspector limit")
        self.initial_stat = info
        self.size = info.st_size
        try:
            self.handle = self.path.open("rb", buffering=0)
        except OSError as error:
            reject(f"Cannot open submission read-only: {error}")
        self._parse()
        return self

    def __exit__(self, _kind: Any, _value: Any, _traceback: Any) -> None:
        if self.handle is not None:
            self.handle.close()
            self.handle = None
        if self.initial_stat is not None:
            try:
                final = os.stat(self.path)
                before = (self.initial_stat.st_size, self.initial_stat.st_mtime_ns, getattr(self.initial_stat, "st_ino", 0))
                after = (final.st_size, final.st_mtime_ns, getattr(final, "st_ino", 0))
                if before != after and _kind is None:
                    reject("Archive changed while it was being inspected")
            except OSError as error:
                if _kind is None:
                    reject(f"Archive disappeared while loading: {error}")

    def _read_at(self, offset: int, count: int, label: str) -> bytes:
        if self.handle is None or offset < 0 or count < 0 or offset > self.size or count > self.size - offset:
            reject(f"{label} is outside the archive")
        self.handle.seek(offset)
        result = self.handle.read(count)
        if len(result) != count:
            reject(f"Short read of {label}")
        return result

    @staticmethod
    def _name(raw: bytes) -> str:
        if not raw or len(raw) > 512:
            reject("Unsafe member-name length")
        try:
            name = raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            reject("Member name is not strict UTF-8")
        parts = name.split("/")
        if (
            not name.isascii() or name.startswith("/") or name.endswith("/") or
            "\\" in name or ":" in name or any(part in {"", ".", ".."} for part in parts) or
            any(re.fullmatch(r"[A-Za-z0-9_.-]+", part) is None for part in parts)
        ):
            reject(f"Unsafe member path: {name!r}")
        return name

    def _parse(self) -> None:
        tail_size = min(self.size, 65_557)
        tail = self._read_at(self.size - tail_size, tail_size, "ZIP tail")
        marker = tail.rfind(b"PK\x05\x06")
        if marker < 0 or marker + self.EOCD.size != len(tail):
            reject("ZIP end record is absent, commented, or followed by hidden data")
        sig, disk, central_disk, disk_count, total_count, central_size, central_offset, comment = self.EOCD.unpack_from(tail, marker)
        directory_end = self.size - tail_size + marker
        if (
            sig != 0x06054B50 or disk or central_disk or disk_count != total_count or comment or
            total_count < 1 or total_count > 32 or central_offset + central_size != directory_end
        ):
            reject("ZIP end/central directory is not canonical single-disk ZIP32")
        position = central_offset
        previous_name = ""
        total_expanded = 0
        members: list[Member] = []
        for _ in range(total_count):
            raw_header = self._read_at(position, self.CENTRAL.size, "central header")
            position += self.CENTRAL.size
            fields = self.CENTRAL.unpack(raw_header)
            (
                signature, made, needed, flags, method, dos_time, dos_date, crc32,
                compressed, expanded, name_length, extra_length, member_comment,
                start_disk, internal_attr, external_attr, local_offset,
            ) = fields
            if (
                signature != 0x02014B50 or made != 20 or needed != 20 or flags != 0x0800 or
                method not in (0, 8) or dos_time != 0 or dos_date != 33 or extra_length or
                member_comment or start_disk or internal_attr or external_attr
            ):
                reject("ZIP central member metadata is not collector-canonical")
            name = self._name(self._read_at(position, name_length, "central name"))
            position += name_length
            if previous_name and name <= previous_name:
                reject("ZIP member names are duplicated or unsorted")
            previous_name = name
            if method == 0 and compressed != expanded:
                reject("Stored member has unequal compressed/expanded sizes")
            if expanded > self.MAX_MEMBER or (expanded and not compressed):
                reject("Member expanded size is unsafe")
            if expanded / max(compressed, 1) > self.MAX_RATIO:
                reject("Member compression ratio exceeds the inspector limit")
            total_expanded += expanded
            if total_expanded > self.MAX_EXPANDED:
                reject("Total expanded size exceeds the inspector limit")
            members.append(Member(name, "", crc32, compressed, expanded, method, local_offset))
        if position != central_offset + central_size:
            reject("Central-directory size is inconsistent")

        tops = {member.name.split("/", 1)[0] for member in members}
        if len(tops) != 1:
            reject("Archive must have exactly one top-level session directory")
        top = next(iter(tops))
        if not top.startswith("session_") or SESSION_ID_RE.fullmatch(top[8:]) is None:
            reject("Top-level session identity is invalid")
        expected_offset = 0
        for member in members:
            if member.local_offset != expected_offset:
                reject("Local ZIP members are not contiguous and ordered")
            raw_header = self._read_at(member.local_offset, self.LOCAL.size, "local header")
            signature, needed, flags, method, dos_time, dos_date, crc32, compressed, expanded, name_length, extra_length = self.LOCAL.unpack(raw_header)
            if (
                signature != 0x04034B50 or needed != 20 or flags != 0x0800 or method != member.method or
                dos_time != 0 or dos_date != 33 or crc32 != member.crc32 or compressed != member.compressed or
                expanded != member.expanded or extra_length
            ):
                reject("Local and central ZIP metadata differ")
            raw_name = self._read_at(member.local_offset + self.LOCAL.size, name_length, "local name")
            if self._name(raw_name) != member.name:
                reject("Local and central member names differ")
            member.data_offset = member.local_offset + self.LOCAL.size + name_length
            expected_offset = member.data_offset + member.compressed
            prefix = top + "/"
            if not member.name.startswith(prefix):
                reject("Member escaped the sole session directory")
            member.relative = member.name[len(prefix):]
            if member.expanded > ARTIFACT_MAX_EXPANDED.get(member.relative, self.MAX_MEMBER):
                reject(f"{member.relative} exceeds its release-specific expanded-size limit")
        if expected_offset != central_offset:
            reject("ZIP contains a gap/hidden bytes before its central directory")
        relative = {member.relative for member in members}
        if relative != CONTROL_ARTIFACTS | DATA_ARTIFACTS:
            reject("Archive artifact inventory is not exactly Capture v0.4.1")
        if total_expanded / max(self.size, 1) > self.MAX_RATIO:
            reject("Overall compression ratio exceeds the inspector limit")
        self.members = members
        self.by_relative = {member.relative: member for member in members}
        self.session_id = top[8:]

    def _compressed_chunks(self, member: Member) -> Iterator[bytes]:
        assert self.handle is not None
        self.handle.seek(member.data_offset)
        remaining = member.compressed
        while remaining:
            data = self.handle.read(min(self.CHUNK, remaining))
            if not data:
                reject(f"Truncated member {member.relative}")
            remaining -= len(data)
            yield data

    def chunks(self, relative: str) -> Iterator[bytes]:
        member = self.by_relative.get(relative)
        if member is None:
            reject(f"Missing member {relative}")
        produced = 0
        crc = 0
        if member.method == 0:
            for data in self._compressed_chunks(member):
                produced += len(data)
                crc = zlib.crc32(data, crc)
                yield data
        else:
            inflater = zlib.decompressobj(-zlib.MAX_WBITS)
            for compressed in self._compressed_chunks(member):
                pending = compressed
                while pending:
                    budget = min(self.CHUNK, member.expanded - produced + 1)
                    if budget <= 0:
                        reject(f"Expanded-size overrun in {relative}")
                    try:
                        data = inflater.decompress(pending, budget)
                    except zlib.error as error:
                        reject(f"Invalid Deflate stream in {relative}: {error}")
                    pending = inflater.unconsumed_tail
                    if data:
                        produced += len(data)
                        if produced > member.expanded:
                            reject(f"Expanded-size overrun in {relative}")
                        crc = zlib.crc32(data, crc)
                        yield data
                    if inflater.eof:
                        if pending or inflater.unused_data:
                            reject(f"Trailing Deflate bytes in {relative}")
                        if self.handle is not None and self.handle.tell() != member.data_offset + member.compressed:
                            reject(f"Deflate stream ends before declared extent in {relative}")
                        break
                    if not data and not pending:
                        break
            if not inflater.eof:
                reject(f"Truncated Deflate stream in {relative}")
        if produced != member.expanded or (crc & 0xFFFFFFFF) != member.crc32:
            reject(f"Expanded size/CRC mismatch in {relative}")

    def read(self, relative: str, maximum: int) -> bytes:
        member = self.by_relative[relative]
        if member.expanded > maximum:
            reject(f"Member exceeds bounded read limit: {relative}")
        return b"".join(self.chunks(relative))

    def verified_chunks(self, relative: str) -> Iterator[bytes]:
        expected = self.expected_hashes.get(relative)
        if expected is None:
            reject(f"Member is absent from checksum inventory: {relative}")
        digest = hashlib.sha256()
        for chunk in self.chunks(relative):
            digest.update(chunk)
            yield chunk
        if digest.hexdigest() != expected:
            reject(f"SHA-256 mismatch in {relative}")

    def read_verified(self, relative: str, maximum: int) -> bytes:
        if self.by_relative[relative].expanded > maximum:
            reject(f"Member exceeds bounded read limit: {relative}")
        return b"".join(self.verified_chunks(relative))

    def load_controls(self) -> dict[str, Any]:
        checksum_bytes = self.read("checksums.sha256", 16 << 20)
        if not checksum_bytes.endswith(b"\n") or b"\r" in checksum_bytes:
            reject("checksums.sha256 is not canonical LF text")
        hashes: dict[str, str] = {}
        previous = ""
        for line in checksum_bytes.splitlines():
            match = re.fullmatch(br"([0-9a-f]{64})  ([A-Za-z0-9_./-]+)", line)
            if match is None:
                reject("Malformed checksum inventory line")
            name = match.group(2).decode("ascii")
            if previous and name <= previous:
                reject("Checksum inventory is duplicated/unsorted")
            previous = name
            hashes[name] = match.group(1).decode("ascii")
        if set(hashes) != DATA_ARTIFACTS:
            reject("Checksum inventory differs from Capture v0.4.1")
        complete = strict_json(self.read("COMPLETE", 1 << 20), "COMPLETE")
        if (
            not isinstance(complete, dict) or complete.get("schema") != COMPLETE_SCHEMA or
            complete.get("session_id") != self.session_id or complete.get("artifact_count") != len(DATA_ARTIFACTS) or
            complete.get("checksums_sha256") != hashlib.sha256(checksum_bytes).hexdigest()
        ):
            reject("COMPLETE does not seal this session/inventory")
        self.expected_hashes = hashes
        manifest = strict_json(self.read_verified("manifest.json", 16 << 20), "manifest.json")
        if not isinstance(manifest, dict):
            reject("manifest.json is not an object")
        expected = {
            "schema": SESSION_SCHEMA,
            "session_id": self.session_id,
            "application_version": RELEASE_VERSION,
            "source_revision": RELEASE_REVISION,
            "protocol_id": PROTOCOL_ID,
            "protocol_sha256": PROTOCOL_SHA256,
        }
        if any(manifest.get(key) != value for key, value in expected.items()):
            reject("Manifest identity/release/protocol does not match Capture v0.4.1")
        if not manifest.get("verified_authoritative_source"):
            reject("Manifest does not identify an authoritative capture source")
        bounded_int(manifest.get("qpc_frequency"), "manifest qpc_frequency", 1, 10**12)
        bounded_int(manifest.get("event_count"), "manifest event_count", 0, 1_000_000)
        try:
            decoded_count = int(manifest.get("decoded_reports", "-1"))
        except (TypeError, ValueError):
            reject("Manifest decoded-report count is invalid")
        if decoded_count < 0 or decoded_count > 5_000_000:
            reject("Manifest decoded-report count exceeds inspector bounds")
        device = manifest.get("device")
        if not isinstance(device, dict):
            reject("Manifest device is not an object")
        bounded_int(device.get("usb_bus"), "manifest USB bus", 1, 0xFFFF)
        bounded_int(device.get("usb_device"), "manifest USB device", 1, 0xFFFF)
        bounded_int(device.get("interrupt_in_endpoint"), "manifest interrupt endpoint", 0x81, 0x8F)
        if HEX64_RE.fullmatch(str(device.get("hid_descriptor_sha256", ""))) is None:
            reject("Manifest HID descriptor SHA-256 is invalid")
        if HEX64_RE.fullmatch(str(device.get("selection_token", ""))) is None:
            reject("Manifest selected-device token is invalid")
        return manifest

    def raw_sha256(self) -> str:
        if self.handle is None:
            reject("Archive handle is closed")
        digest = hashlib.sha256()
        self.handle.seek(0)
        remaining = self.size
        while remaining:
            chunk = self.handle.read(min(self.CHUNK, remaining))
            if not chunk:
                reject("Archive changed during raw hashing")
            digest.update(chunk)
            remaining -= len(chunk)
        return digest.hexdigest()


class ChunkReader:
    def __init__(self, chunks: Iterable[bytes], label: str) -> None:
        self.iterator = iter(chunks)
        self.buffer = bytearray()
        self.offset = 0
        self.eof = False
        self.label = label

    def _available(self) -> int:
        return len(self.buffer) - self.offset

    def _fill(self, count: int) -> None:
        while self._available() < count and not self.eof:
            try:
                chunk = next(self.iterator)
            except StopIteration:
                self.eof = True
                break
            if self.offset and (self.offset > (1 << 20) or self.offset * 2 > len(self.buffer)):
                del self.buffer[:self.offset]
                self.offset = 0
            self.buffer.extend(chunk)

    def read(self, count: int, allow_eof: bool = False) -> bytes:
        self._fill(count)
        if allow_eof and self._available() == 0 and self.eof:
            return b""
        if self._available() < count:
            reject(f"Truncated {self.label}")
        result = bytes(self.buffer[self.offset:self.offset + count])
        self.offset += count
        return result

    def finish(self) -> None:
        self._fill(1)
        if self._available():
            reject(f"Trailing bytes in {self.label}")


def iter_lines(chunks: Iterable[bytes], label: str) -> Iterator[bytes]:
    buffer = bytearray()
    for chunk in chunks:
        buffer.extend(chunk)
        while True:
            newline = buffer.find(b"\n")
            if newline < 0:
                break
            line = bytes(buffer[:newline])
            del buffer[:newline + 1]
            if not line or len(line) > (4 << 20) or line.endswith(b"\r"):
                reject(f"Unsafe/noncanonical JSONL record in {label}")
            yield line
        if len(buffer) > (4 << 20):
            reject(f"Oversized JSONL record in {label}")
    if buffer:
        reject(f"{label} lacks a final LF")


def iter_journal(archive: SafeArchive, relative: str, schema: str) -> Iterator[dict[str, Any]]:
    for sequence, line in enumerate(iter_lines(archive.verified_chunks(relative), relative)):
        match = CRC_PREFIX_RE.match(line)
        if match is None:
            reject(f"Missing canonical record CRC in {relative}")
        source = b"{" + line[match.end():]
        if f"{zlib.crc32(source) & 0xFFFFFFFF:08x}".encode() != match.group(1):
            reject(f"Per-record CRC mismatch in {relative}")
        record = strict_json(line, f"{relative} record {sequence}")
        if not isinstance(record, dict) or record.get("schema") != schema or record.get("sequence") != sequence:
            reject(f"Schema/sequence mismatch in {relative}")
        yield record


def read_varuint(data: memoryview, offset: int) -> tuple[int, int]:
    value = 0
    start = offset
    for shift in range(0, 64, 7):
        if offset >= len(data):
            reject("Truncated ABCR2 varuint")
        byte = int(data[offset])
        offset += 1
        if shift == 63 and byte & 0xFE:
            reject("ABCR2 varuint overflow")
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if offset - start > 1 and value < (1 << (7 * (offset - start - 1))):
                reject("Overlong ABCR2 varuint")
            return value, offset
    reject("ABCR2 varuint overflow")


def read_varint(data: memoryview, offset: int) -> tuple[int, int]:
    value, offset = read_varuint(data, offset)
    return (value >> 1) ^ -(value & 1), offset


@dataclass(slots=True)
class SessionData:
    path: Path
    manifest: dict[str, Any]
    events: list[dict[str, Any]]
    report_qpc: array
    report_dx: array
    report_dy: array
    report_buttons: array
    raw_qpc: array
    raw_dx: array
    raw_dy: array
    qpc_frequency: int
    archive_sha256: str
    loaded_seconds: float


def parse_events(archive: SafeArchive, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    qpc_frequency = int(manifest.get("qpc_frequency", 0))
    for sequence, event in enumerate(iter_journal(archive, "gameplay/events.jsonl", EVENT_SCHEMA)):
        if sequence >= 1_000_000:
            reject("Event count exceeds inspector limit")
        if (
            event.get("event_id") != sequence or event.get("record_type") != "trainer_event" or
            event.get("session_id") != manifest.get("session_id") or
            event.get("user_id") != manifest.get("user_id") or
            event.get("qpc_frequency") != qpc_frequency
        ):
            reject("Event identity/clock differs from manifest")
        generated_qpc = event.get("target_generated_qpc")
        if not isinstance(generated_qpc, int) or isinstance(generated_qpc, bool) or generated_qpc <= 0:
            reject(f"Event {sequence} has invalid target_generated_qpc")
        presented_qpc = event.get("first_presented_qpc")
        start_qpc = event.get("event_start_qpc")
        for key, value in (("first_presented_qpc", presented_qpc), ("event_start_qpc", start_qpc)):
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value <= 0
            ):
                reject(f"Event {sequence} has invalid {key}")
        if isinstance(presented_qpc, int) and presented_qpc < generated_qpc:
            reject(f"Event {sequence} presentation predates generation")
        if isinstance(start_qpc, int) and isinstance(presented_qpc, int) and start_qpc < presented_qpc:
            reject(f"Event {sequence} start predates presentation")
        if not isinstance(event.get("natural_outcome"), str) or not isinstance(event.get("technical_outcome"), str):
            reject(f"Event {sequence} outcome fields are invalid")
        for name in ("generation_camera", "presentation_camera", "final_camera"):
            camera = event.get(name)
            if not isinstance(camera, dict):
                reject(f"Event {sequence} {name} is not an object")
            bounded_int(camera.get("x_counts"), f"event {sequence} {name}.x", -10**12, 10**12)
            bounded_int(camera.get("y_counts"), f"event {sequence} {name}.y", -10**12, 10**12)
        finite_number(event.get("target_x_counts"), f"event {sequence} target_x")
        finite_number(event.get("target_y_counts"), f"event {sequence} target_y")
        bounded_int(event.get("target_radius_counts"), f"event {sequence} target radius", 1, 10**9)
        for name in (
            "initial_distance_counts", "closest_swept_distance_counts",
            "inside_total_ms", "maximum_consecutive_inside_ms",
        ):
            finite_number(event.get(name), f"event {sequence} {name}", 0.0, 10**12)
        target = event.get("realized_target")
        if not isinstance(target, dict) or target.get("protocol_sha256") != PROTOCOL_SHA256:
            reject(f"Event {sequence} has invalid realized-target provenance")
        if not isinstance(target.get("task_type"), str) or not isinstance(target.get("challenge_id"), str):
            reject(f"Event {sequence} realized target task/challenge is invalid")
        for name in ("target_x_counts", "target_y_counts"):
            finite_number(target.get(name), f"event {sequence} realized {name}")
        clicks = event.get("click_hypotheses")
        if not isinstance(clicks, list) or len(clicks) > 1024:
            reject(f"Event {sequence} click hypotheses are invalid")
        for click in clicks:
            if not isinstance(click, dict):
                reject(f"Event {sequence} click hypothesis is not an object")
            bounded_int(click.get("qpc"), f"event {sequence} click qpc", 1, 0x7FFFFFFFFFFFFFFF)
            position = click.get("post_delta_position")
            if not isinstance(position, dict):
                reject(f"Event {sequence} click position is invalid")
            bounded_int(position.get("x_counts"), f"event {sequence} click x", -10**12, 10**12)
            bounded_int(position.get("y_counts"), f"event {sequence} click y", -10**12, 10**12)
        render = event.get("render_evidence")
        if not isinstance(render, dict):
            reject(f"Event {sequence} render evidence is invalid")
        finite_number(render.get("pixels_per_count_x"), f"event {sequence} render scale", 1.0e-12, 10**6)
        bounded_int(render.get("viewport_width_px"), f"event {sequence} viewport width", 64, 100_000)
        bounded_int(render.get("viewport_height_px"), f"event {sequence} viewport height", 64, 100_000)
        events.append(event)
    if len(events) != manifest.get("event_count"):
        reject("Manifest event count differs from the event journal")
    return events


def parse_reports(archive: SafeArchive, manifest: dict[str, Any]) -> tuple[array, array, array, array, int]:
    descriptor = archive.read_verified("capture/hid_report_descriptor.bin", 1 << 20)
    reader = ChunkReader(archive.verified_chunks("capture/mouse_reports.abcr2"), "ABCR2 report stream")
    if reader.read(8) != b"ABCRPT2\x00":
        reject("ABCR2 magic is invalid")
    version, bus, device, endpoint, reserved, evidence_length, spec_length, qpc_frequency = struct.unpack(
        "<HHHBBIIQ", reader.read(24)
    )
    manifest_device = manifest.get("device", {})
    if (
        version != 2 or reserved or evidence_length < 1 or evidence_length > (1 << 20) or
        spec_length < 1 or spec_length > (1 << 20) or
        (bus, device, endpoint, qpc_frequency) != (
            manifest_device.get("usb_bus"), manifest_device.get("usb_device"),
            manifest_device.get("interrupt_in_endpoint"), manifest.get("qpc_frequency"),
        )
    ):
        reject("ABCR2 header differs from the certified manifest identity")
    try:
        descriptor_sha = reader.read(64).decode("ascii", "strict")
    except UnicodeDecodeError:
        reject("ABCR2 descriptor SHA is not ASCII")
    evidence = reader.read(evidence_length)
    spec = reader.read(spec_length)
    if (
        descriptor_sha != manifest_device.get("hid_descriptor_sha256") or
        hashlib.sha256(evidence).hexdigest() != descriptor_sha or evidence != descriptor or
        not spec.startswith(b"abdc.hid.decoder.v1\n") or b"\x00" in spec
    ):
        reject("ABCR2 descriptor/decoder evidence is inconsistent")

    qpc_values = array("q")
    dx_values = array("i")
    dy_values = array("i")
    button_values = array("I")
    previous_sequence: int | None = None
    previous_pcap: int | None = None
    previous_capture: int | None = None
    previous_qpc: int | None = None
    while True:
        magic = reader.read(4, allow_eof=True)
        if not magic:
            break
        if magic != b"RBLK":
            reject("ABCR2 block magic is invalid")
        block_size, block_count, expected_crc = struct.unpack("<III", reader.read(12))
        if block_size < 1 or block_size > (16 << 20) or block_count < 1 or block_count > 65_536:
            reject("ABCR2 block header exceeds safe limits")
        block = reader.read(block_size)
        if (zlib.crc32(block) & 0xFFFFFFFF) != expected_crc:
            reject("ABCR2 block CRC mismatch")
        data = memoryview(block)
        offset = 0
        for _ in range(block_count):
            sequence_delta, offset = read_varuint(data, offset)
            pcap_delta, offset = read_varuint(data, offset)
            report_index, offset = read_varuint(data, offset)
            reports_in_transfer, offset = read_varuint(data, offset)
            capture_delta, offset = read_varint(data, offset)
            qpc_delta, offset = read_varint(data, offset)
            sequence = sequence_delta if previous_sequence is None else previous_sequence + sequence_delta
            pcap_sequence = pcap_delta if previous_pcap is None else previous_pcap + pcap_delta
            capture_timestamp = capture_delta if previous_capture is None else previous_capture + capture_delta
            qpc = qpc_delta if previous_qpc is None else previous_qpc + qpc_delta
            if (
                (previous_sequence is not None and sequence <= previous_sequence) or
                (previous_pcap is not None and pcap_sequence < previous_pcap) or
                (previous_qpc is not None and qpc < previous_qpc) or qpc <= 0 or
                reports_in_transfer < 1 or report_index >= reports_in_transfer
            ):
                reject("ABCR2 report ordering/transfer position is invalid")
            if offset + 22 > len(data):
                reject("Truncated ABCR2 fixed record")
            _irp, status, _function, record_bus, record_device = struct.unpack_from("<QIHHH", data, offset)
            offset += 18
            record_endpoint, transfer, info, _report_id = struct.unpack_from("<BBBB", data, offset)
            offset += 4
            move_x, offset = read_varint(data, offset)
            move_y, offset = read_varint(data, offset)
            _wheel, offset = read_varint(data, offset)
            _horizontal_wheel, offset = read_varint(data, offset)
            buttons, offset = read_varuint(data, offset)
            quality, offset = read_varuint(data, offset)
            payload_length, offset = read_varuint(data, offset)
            if (
                not (-0x80000000 <= move_x <= 0x7FFFFFFF and -0x80000000 <= move_y <= 0x7FFFFFFF) or
                buttons > 0xFFFFFFFF or quality > 0xFFFFFFFF or quality & ~0x3 or
                payload_length < 1 or payload_length > 4096 or offset + payload_length > len(data) or
                status != 0 or transfer != 1 or info != 1 or
                (record_bus, record_device, record_endpoint) != (bus, device, endpoint)
            ):
                reject("ABCR2 report violates the locked successful interrupt-IN contract")
            offset += payload_length
            qpc_values.append(qpc)
            dx_values.append(move_x)
            dy_values.append(move_y)
            button_values.append(buttons)
            if len(qpc_values) > 5_000_000:
                reject("Decoded report count exceeds inspector limit")
            previous_sequence = sequence
            previous_pcap = pcap_sequence
            previous_capture = capture_timestamp
            previous_qpc = qpc
        if offset != len(data):
            reject("ABCR2 block has trailing bytes")
    reader.finish()
    try:
        expected_count = int(manifest.get("decoded_reports", "-1"))
    except (TypeError, ValueError):
        reject("Manifest decoded-report count is invalid")
    if len(qpc_values) != expected_count:
        reject("Manifest decoded-report count differs from ABCR2")
    return qpc_values, dx_values, dy_values, button_values, int(qpc_frequency)


def parse_raw_witness(archive: SafeArchive, manifest: dict[str, Any]) -> tuple[array, array, array]:
    qpc_values = array("q")
    dx_values = array("i")
    dy_values = array("i")
    device = manifest.get("device", {})
    selection_token = device.get("selection_token")
    for record in iter_journal(archive, "gameplay/raw_input_witness.jsonl", RAW_SCHEMA):
        if (
            record.get("record_type") != "raw_input_witness_packet" or
            record.get("authority") != "non_authoritative_windows_raw_input_witness" or
            record.get("authoritative") is not False or
            record.get("session_id") != manifest.get("session_id") or
            record.get("user_id") != manifest.get("user_id") or
            record.get("qpc_frequency") != manifest.get("qpc_frequency")
        ):
            reject("Raw Input witness identity/authority differs from manifest")
        if not record.get("selected_device"):
            continue
        qpc = record.get("receipt_qpc")
        move_x = record.get("dx_counts")
        move_y = record.get("dy_counts")
        if (
            record.get("device_token") != selection_token or
            not isinstance(qpc, int) or isinstance(qpc, bool) or qpc <= 0 or
            not isinstance(move_x, int) or isinstance(move_x, bool) or not -0x80000000 <= move_x <= 0x7FFFFFFF or
            not isinstance(move_y, int) or isinstance(move_y, bool) or not -0x80000000 <= move_y <= 0x7FFFFFFF
        ):
            reject("Selected Raw Input witness packet is malformed")
        if qpc_values and qpc < qpc_values[-1]:
            reject("Raw Input witness QPC regressed")
        qpc_values.append(qpc)
        dx_values.append(move_x)
        dy_values.append(move_y)
        if len(qpc_values) > 5_000_000:
            reject("Raw Input witness exceeds inspector limit")
    return qpc_values, dx_values, dy_values


def load_session(path: Path, progress: Callable[[str], None] | None = None) -> SessionData:
    started = time.perf_counter()
    tell = progress or (lambda _message: None)
    tell("Checking canonical ZIP and sealed controls…")
    with SafeArchive(path) as archive:
        manifest = archive.load_controls()
        archive_sha = archive.raw_sha256()
        tell("Loading and verifying gameplay events…")
        events = parse_events(archive, manifest)
        tell("Loading authoritative USB report stream…")
        report_qpc, report_dx, report_dy, report_buttons, qpc_frequency = parse_reports(archive, manifest)
        tell("Loading independent Raw Input witness…")
        raw_qpc, raw_dx, raw_dy = parse_raw_witness(archive, manifest)
    return SessionData(
        path=path,
        manifest=manifest,
        events=events,
        report_qpc=report_qpc,
        report_dx=report_dx,
        report_dy=report_dy,
        report_buttons=report_buttons,
        raw_qpc=raw_qpc,
        raw_dx=raw_dx,
        raw_dy=raw_dy,
        qpc_frequency=qpc_frequency,
        archive_sha256=archive_sha,
        loaded_seconds=time.perf_counter() - started,
    )


def event_start_qpc(event: dict[str, Any]) -> int:
    for name in ("event_start_qpc", "first_presented_qpc", "target_generated_qpc"):
        value = event.get(name)
        if isinstance(value, int) and not isinstance(value, bool):
            return int(value)
    reject("Event has no usable start/generation QPC")


def event_end_qpc(event: dict[str, Any], include_tail: bool = True) -> int:
    if include_tail and isinstance(event.get("tail_end_qpc"), int):
        return int(event["tail_end_qpc"])
    if isinstance(event.get("natural_resolution_qpc"), int):
        return int(event["natural_resolution_qpc"])
    if isinstance(event.get("technical_interruption_qpc"), int):
        return int(event["technical_interruption_qpc"])
    return event_start_qpc(event)


def event_duration_ms(event: dict[str, Any], qpc_frequency: int) -> float:
    return (event_end_qpc(event, include_tail=False) - event_start_qpc(event)) * 1000.0 / qpc_frequency


def event_outcome_label(event: dict[str, Any]) -> str:
    natural = str(event.get("natural_outcome", "none"))
    technical = str(event.get("technical_outcome", "none"))
    if natural != "none" and technical != "none":
        return f"{natural} + tail:{technical}"
    if technical != "none":
        return f"technical:{technical}"
    return natural


def sampled_polyline(points: list[tuple[float, float]], maximum: int = 2500) -> list[tuple[float, float]]:
    if len(points) <= maximum:
        return points
    step = max(1, math.ceil(len(points) / maximum))
    result = points[::step]
    if result[-1] != points[-1]:
        result.append(points[-1])
    return result


def event_paths(data: SessionData, event: dict[str, Any]) -> dict[str, Any]:
    start = event_start_qpc(event)
    end = event_end_qpc(event, include_tail=True)
    active_end = event_end_qpc(event, include_tail=False)
    presentation = event.get("presentation_camera") or event.get("generation_camera", {})
    start_x = float(presentation.get("x_counts", 0))
    start_y = float(presentation.get("y_counts", 0))

    usb_lo = bisect.bisect_right(data.report_qpc, start)
    usb_hi = bisect.bisect_right(data.report_qpc, end)
    x, y = start_x, start_y
    usb_points: list[tuple[float, float]] = [(x, y)]
    usb_timeline_ms: list[float] = [0.0]
    usb_timeline: list[tuple[float, float, float, float]] = [(x, y, 0.0, 0.0)]
    direction_x = 0.0
    direction_y = 0.0
    speeds: list[tuple[float, float]] = []
    current_bucket: int | None = None
    bucket_x = 0
    bucket_y = 0
    for index in range(usb_lo, usb_hi):
        move_x = int(data.report_dx[index])
        move_y = -int(data.report_dy[index])  # native HID Y-down -> canonical Y-up
        x += move_x
        y += move_y
        if move_x or move_y:
            direction_x = float(move_x)
            direction_y = float(move_y)
            usb_points.append((x, y))
        milliseconds = max(0.0, (int(data.report_qpc[index]) - start) * 1000.0 / data.qpc_frequency)
        usb_timeline_ms.append(milliseconds)
        usb_timeline.append((x, y, direction_x, direction_y))
        bucket = (int(data.report_qpc[index]) - start) * 250 // data.qpc_frequency
        if current_bucket is None:
            current_bucket = bucket
        if bucket != current_bucket:
            speeds.append((current_bucket * 4.0, math.hypot(bucket_x, bucket_y)))
            current_bucket = bucket
            bucket_x = 0
            bucket_y = 0
        bucket_x += move_x
        bucket_y += move_y
    if current_bucket is not None:
        speeds.append((current_bucket * 4.0, math.hypot(bucket_x, bucket_y)))
    total_duration_ms = max(0.0, (end - start) * 1000.0 / data.qpc_frequency)
    if usb_timeline_ms[-1] < total_duration_ms:
        usb_timeline_ms.append(total_duration_ms)
        usb_timeline.append((x, y, direction_x, direction_y))

    raw_lo = bisect.bisect_right(data.raw_qpc, start)
    raw_hi = bisect.bisect_right(data.raw_qpc, end)
    x, y = start_x, start_y
    raw_points: list[tuple[float, float]] = [(x, y)]
    for index in range(raw_lo, raw_hi):
        x += int(data.raw_dx[index])
        y += int(data.raw_dy[index])  # journal already stores canonical Y-up
        if data.raw_dx[index] or data.raw_dy[index]:
            raw_points.append((x, y))
    return {
        "usb": sampled_polyline(usb_points),
        "usb_timeline_ms": usb_timeline_ms,
        "usb_timeline": usb_timeline,
        "raw": sampled_polyline(raw_points),
        "speed": speeds,
        "active_duration_ms": (active_end - start) * 1000.0 / data.qpc_frequency,
        "tail_duration_ms": (end - active_end) * 1000.0 / data.qpc_frequency,
        "usb_report_count": usb_hi - usb_lo,
        "raw_packet_count": raw_hi - raw_lo,
    }


def playback_sample(paths: dict[str, Any], elapsed_ms: float) -> dict[str, Any]:
    """Interpolate the authoritative USB cursor and its already-travelled trail."""
    times: list[float] = paths["usb_timeline_ms"]
    timeline: list[tuple[float, float, float, float]] = paths["usb_timeline"]
    if not times or len(times) != len(timeline):
        raise ValueError("invalid playback timeline")
    duration = max(0.0, paths["active_duration_ms"] + paths["tail_duration_ms"])
    current_ms = min(max(float(elapsed_ms), 0.0), duration)
    index = max(0, min(bisect.bisect_right(times, current_ms) - 1, len(times) - 1))
    x, y, direction_x, direction_y = timeline[index]
    if index + 1 < len(timeline) and times[index + 1] > times[index]:
        fraction = min(max((current_ms - times[index]) / (times[index + 1] - times[index]), 0.0), 1.0)
        next_x, next_y, next_direction_x, next_direction_y = timeline[index + 1]
        x += (next_x - x) * fraction
        y += (next_y - y) * fraction
        if next_x != timeline[index][0] or next_y != timeline[index][1]:
            direction_x = next_x - timeline[index][0]
            direction_y = next_y - timeline[index][1]
        elif not direction_x and not direction_y:
            direction_x = next_direction_x
            direction_y = next_direction_y
    trail = [(sample[0], sample[1]) for sample in timeline[:index + 1]]
    if not trail or trail[-1] != (x, y):
        trail.append((x, y))
    return {
        "elapsed_ms": current_ms,
        "x": x,
        "y": y,
        "direction_x": direction_x,
        "direction_y": direction_y,
        "trail": sampled_polyline(trail),
    }


class ManualReviewStore:
    def __init__(self, session: SessionData) -> None:
        self.session = session
        self.path = session.path.with_name(session.path.stem + "_MANUAL_REVIEW.json")
        self.reviews: dict[str, dict[str, str]] = {}
        self.load_warning = ""
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            if self.path.stat().st_size > (4 << 20):
                raise ValueError("sidecar exceeds 4 MiB")
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or payload.get("schema") != "abcurves.manual_event_review.v1":
                raise ValueError("unknown sidecar schema")
            if payload.get("archive_sha256") != self.session.archive_sha256:
                self.load_warning = "Existing review sidecar belongs to different archive bytes; it was not loaded."
                return
            raw_reviews = payload.get("reviews", {})
            if isinstance(raw_reviews, dict):
                for event_id, review in raw_reviews.items():
                    if (
                        event_id.isdecimal() and isinstance(review, dict) and
                        review.get("label") in REVIEW_LABELS and isinstance(review.get("note", ""), str)
                    ):
                        self.reviews[event_id] = {
                            "label": review["label"],
                            "note": review.get("note", "")[:10_000],
                            "updated_at_utc": str(review.get("updated_at_utc", ""))[:64],
                        }
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
            self.load_warning = f"Review sidecar was ignored: {error}"

    def save(self) -> None:
        payload = {
            "schema": "abcurves.manual_event_review.v1",
            "session_id": self.session.manifest.get("session_id"),
            "archive_filename": self.session.path.name,
            "archive_sha256": self.session.archive_sha256,
            "reviews": self.reviews,
        }
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as output:
                json.dump(payload, output, ensure_ascii=False, indent=2, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def set(self, event_id: int, label: str, note: str) -> None:
        if label not in REVIEW_LABELS:
            raise ValueError("Choose a review label")
        self.reviews[str(event_id)] = {
            "label": label,
            "note": note[:10_000],
            "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        self.save()

    def clear(self, event_id: int) -> None:
        self.reviews.pop(str(event_id), None)
        self.save()


class WindowsDropTarget:
    """Native WM_DROPFILES bridge; no tkdnd package is required."""

    def __init__(self, root: tk.Tk, callback: Callable[[Path], None]) -> None:
        self.root = root
        self.callback = callback
        self.hwnd = 0
        self.old_proc = 0
        self.new_proc: Any = None
        self.available = False
        if os.name != "nt":
            return
        try:
            root.update_idletasks()
            self.hwnd = int(root.winfo_id())
            user32 = ctypes.windll.user32
            shell32 = ctypes.windll.shell32
            lresult = ctypes.c_ssize_t
            wparam = ctypes.c_size_t
            lparam = ctypes.c_ssize_t
            wndproc_type = ctypes.WINFUNCTYPE(lresult, ctypes.c_void_p, ctypes.c_uint, wparam, lparam)
            user32.SetWindowLongPtrW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
            user32.SetWindowLongPtrW.restype = ctypes.c_void_p
            user32.CallWindowProcW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, wparam, lparam]
            user32.CallWindowProcW.restype = lresult
            shell32.DragQueryFileW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_wchar_p, ctypes.c_uint]
            shell32.DragQueryFileW.restype = ctypes.c_uint
            shell32.DragFinish.argtypes = [ctypes.c_void_p]

            def window_proc(hwnd: int, message: int, wp: int, lp: int) -> int:
                if message == 0x0233:  # WM_DROPFILES
                    try:
                        count = shell32.DragQueryFileW(ctypes.c_void_p(wp), 0xFFFFFFFF, None, 0)
                        for index in range(count):
                            length = shell32.DragQueryFileW(ctypes.c_void_p(wp), index, None, 0)
                            buffer = ctypes.create_unicode_buffer(length + 1)
                            shell32.DragQueryFileW(ctypes.c_void_p(wp), index, buffer, length + 1)
                            candidate = Path(buffer.value)
                            if candidate.suffix.lower() == ".zip":
                                self.root.after(0, self.callback, candidate)
                                break
                    finally:
                        shell32.DragFinish(ctypes.c_void_p(wp))
                    return 0
                return int(user32.CallWindowProcW(ctypes.c_void_p(self.old_proc), hwnd, message, wp, lp))

            self.new_proc = wndproc_type(window_proc)
            self.old_proc = int(user32.SetWindowLongPtrW(
                ctypes.c_void_p(self.hwnd), -4, ctypes.cast(self.new_proc, ctypes.c_void_p)
            ) or 0)
            if not self.old_proc:
                raise OSError("SetWindowLongPtrW failed")
            shell32.DragAcceptFiles(ctypes.c_void_p(self.hwnd), True)
            self.available = True
        except (AttributeError, OSError, ValueError):
            self.available = False

    def close(self) -> None:
        if not self.available or not self.hwnd or not self.old_proc:
            return
        try:
            ctypes.windll.shell32.DragAcceptFiles(ctypes.c_void_p(self.hwnd), False)
            ctypes.windll.user32.SetWindowLongPtrW(
                ctypes.c_void_p(self.hwnd), -4, ctypes.c_void_p(self.old_proc)
            )
        except (AttributeError, OSError, ValueError):
            pass
        self.available = False


class InspectorApp:
    COLORS = {
        "background": "#f5f7fa",
        "panel": "#ffffff",
        "grid": "#d9e0e8",
        "text": "#1d2733",
        "muted": "#667382",
        "usb": "#1261a0",
        "raw": "#dc7b13",
        "hit": "#17823b",
        "miss": "#c23b32",
        "timeout": "#b07a00",
        "technical": "#7a48a5",
        "tail": "#697789",
        "cursor": "#d81b60",
    }

    def __init__(self, root: tk.Tk, initial_path: Path | None = None) -> None:
        self.root = root
        self.data: SessionData | None = None
        self.review_store: ManualReviewStore | None = None
        self.filtered_ids: list[int] = []
        self.current_event_id: int | None = None
        self.loading = False
        self._redraw_job: str | None = None
        self._playback_job: str | None = None
        self._playback_enabled = True
        self._playback_running = False
        self._playback_position_ms: float | None = None
        self._playback_anchor_ms = 0.0
        self._playback_anchor_time = 0.0
        self._playback_rate = 0.25
        self._cached_paths_event_id: int | None = None
        self._cached_paths: dict[str, Any] | None = None
        self._build_window()
        self.drop_target = WindowsDropTarget(root, self.open_path)
        self.drop_text.set(
            "Drop a _SEND_THIS.zip here, or use Open. The archive is never extracted."
            if self.drop_target.available else
            "Use Open (or pass a ZIP on the command line). The archive is never extracted."
        )
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        if initial_path is not None:
            self.root.after(100, self.open_path, initial_path)

    def _build_window(self) -> None:
        self.root.title(APP_TITLE)
        self.root.geometry("1500x920")
        self.root.minsize(1050, 680)
        self.root.configure(background=self.COLORS["background"])
        style = ttk.Style(self.root)
        try:
            style.theme_use("vista" if os.name == "nt" else "clam")
        except tk.TclError:
            pass
        style.configure("Title.TLabel", font=("Segoe UI", 13, "bold"))
        style.configure("Muted.TLabel", foreground=self.COLORS["muted"])

        toolbar = ttk.Frame(self.root, padding=(10, 8))
        toolbar.pack(fill="x")
        self.open_button = ttk.Button(toolbar, text="Open ZIP…", command=self.choose_file)
        self.open_button.pack(side="left")
        ttk.Button(toolbar, text="◀ Previous", command=lambda: self.navigate(-1)).pack(side="left", padx=(10, 2))
        ttk.Button(toolbar, text="Next ▶", command=lambda: self.navigate(1)).pack(side="left", padx=2)
        self.play_button = ttk.Button(toolbar, text="▶ Play", command=self.toggle_playback, state="disabled")
        self.play_button.pack(side="left", padx=(10, 2))
        self.loop_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(toolbar, text="Loop", variable=self.loop_var).pack(side="left", padx=(2, 5))
        self.playback_speed_var = tk.StringVar(value="0.25×")
        speed = ttk.Combobox(
            toolbar, textvariable=self.playback_speed_var, state="readonly", width=5,
            values=("0.25×", "0.5×", "1×", "2×", "4×"),
        )
        speed.pack(side="left", padx=(0, 5))
        speed.bind("<<ComboboxSelected>>", self._playback_speed_changed)
        self.playback_status_var = tk.StringVar(value="")
        ttk.Label(toolbar, textvariable=self.playback_status_var, style="Muted.TLabel").pack(side="left", padx=(0, 8))
        ttk.Label(toolbar, text="Event").pack(side="left", padx=(12, 3))
        self.jump_var = tk.StringVar()
        jump = ttk.Entry(toolbar, textvariable=self.jump_var, width=8)
        jump.pack(side="left")
        jump.bind("<Return>", lambda _event: self.jump_to_event())
        ttk.Button(toolbar, text="Go", command=self.jump_to_event).pack(side="left", padx=(3, 10))
        self.session_label = ttk.Label(toolbar, text="No session loaded", style="Title.TLabel")
        self.session_label.pack(side="left", fill="x", expand=True)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(toolbar, textvariable=self.status_var, style="Muted.TLabel").pack(side="right")

        self.drop_text = tk.StringVar()
        drop_bar = tk.Label(
            self.root, textvariable=self.drop_text, anchor="w", padx=12, pady=6,
            background="#e8f1fb", foreground="#294967", font=("Segoe UI", 9),
        )
        drop_bar.pack(fill="x")

        main = ttk.Panedwindow(self.root, orient="horizontal")
        main.pack(fill="both", expand=True, padx=10, pady=(8, 6))

        left = ttk.Frame(main, padding=(0, 0, 8, 0))
        right = ttk.Frame(main)
        main.add(left, weight=1)
        main.add(right, weight=3)

        filter_row = ttk.Frame(left)
        filter_row.pack(fill="x", pady=(0, 5))
        ttk.Label(filter_row, text="Show:").pack(side="left")
        self.filter_var = tk.StringVar(value="All events")
        self.filter_combo = ttk.Combobox(
            filter_row,
            textvariable=self.filter_var,
            state="readonly",
            width=22,
            values=(
                "All events", "Hits", "Miss clicks", "Timeouts", "Technical",
                "Reviewed", "Unreviewed", "Flagged reviews",
            ),
        )
        self.filter_combo.pack(side="left", fill="x", expand=True, padx=(5, 0))
        self.filter_combo.bind("<<ComboboxSelected>>", lambda _event: self.apply_filter())

        columns = ("id", "block", "task", "outcome", "ms", "review")
        self.tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        headings = {"id": "ID", "block": "Block", "task": "Task", "outcome": "Outcome", "ms": "ms", "review": "Review"}
        widths = {"id": 55, "block": 45, "task": 125, "outcome": 100, "ms": 65, "review": 105}
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], minwidth=35, stretch=column in {"task", "outcome", "review"})
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._tree_selected)

        right.rowconfigure(0, weight=4)
        right.rowconfigure(1, weight=2)
        right.columnconfigure(0, weight=3)
        right.columnconfigure(1, weight=2)
        self.path_canvas = tk.Canvas(
            right, background=self.COLORS["panel"], highlightthickness=1,
            highlightbackground=self.COLORS["grid"], cursor="crosshair",
        )
        self.path_canvas.grid(row=0, column=0, columnspan=2, sticky="nsew")
        self.speed_canvas = tk.Canvas(
            right, background=self.COLORS["panel"], highlightthickness=1,
            highlightbackground=self.COLORS["grid"], height=220,
        )
        self.speed_canvas.grid(row=1, column=0, sticky="nsew", pady=(6, 0), padx=(0, 6))
        detail_frame = ttk.Frame(right)
        detail_frame.grid(row=1, column=1, sticky="nsew", pady=(6, 0))
        self.details = tk.Text(
            detail_frame, wrap="word", font=("Consolas", 9), relief="flat",
            background="#fbfcfe", foreground=self.COLORS["text"], padx=8, pady=8,
        )
        detail_scroll = ttk.Scrollbar(detail_frame, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=detail_scroll.set, state="disabled")
        self.details.pack(side="left", fill="both", expand=True)
        detail_scroll.pack(side="right", fill="y")
        self.path_canvas.bind("<Configure>", self.schedule_redraw)
        self.speed_canvas.bind("<Configure>", self.schedule_redraw)

        review = ttk.Frame(self.root, padding=(10, 5, 10, 10))
        review.pack(fill="x")
        ttk.Label(review, text="Manual review:").pack(side="left")
        self.review_label_var = tk.StringVar(value=REVIEW_LABELS[0])
        self.review_combo = ttk.Combobox(
            review, textvariable=self.review_label_var, values=REVIEW_LABELS,
            state="readonly", width=26,
        )
        self.review_combo.pack(side="left", padx=(6, 8))
        ttk.Label(review, text="Note:").pack(side="left")
        self.review_note_var = tk.StringVar()
        self.review_note = ttk.Entry(review, textvariable=self.review_note_var)
        self.review_note.pack(side="left", fill="x", expand=True, padx=(6, 8))
        ttk.Button(review, text="Save review", command=self.save_review).pack(side="left", padx=2)
        ttk.Button(review, text="Clear", command=self.clear_review).pack(side="left", padx=2)
        self.review_status_var = tk.StringVar()
        ttk.Label(review, textvariable=self.review_status_var, style="Muted.TLabel").pack(side="left", padx=(10, 0))

        self.root.bind("<Control-o>", lambda _event: self.choose_file())
        self.root.bind("<Control-s>", lambda _event: self.save_review())
        self.root.bind("<Left>", lambda _event: self.navigate(-1))
        self.root.bind("<Right>", lambda _event: self.navigate(1))
        self.root.bind("<Home>", lambda _event: self.select_filtered_position(0))
        self.root.bind("<End>", lambda _event: self.select_filtered_position(len(self.filtered_ids) - 1))

    def close(self) -> None:
        self._cancel_playback_job()
        self.drop_target.close()
        self.root.destroy()

    def _cancel_playback_job(self) -> None:
        if self._playback_job is not None:
            try:
                self.root.after_cancel(self._playback_job)
            except tk.TclError:
                pass
            self._playback_job = None

    def _reset_playback(self) -> None:
        self._cancel_playback_job()
        self._playback_running = False
        self._playback_position_ms = None
        self._playback_anchor_ms = 0.0
        self._playback_anchor_time = 0.0
        self.play_button.configure(text="■ Stop" if self._playback_enabled else "▶ Play")
        self.playback_status_var.set("")

    def _selected_playback_rate(self) -> float:
        try:
            return float(self.playback_speed_var.get().replace("×", ""))
        except ValueError:
            return 1.0

    def _paths_for_current_event(self) -> dict[str, Any] | None:
        if self.data is None or self.current_event_id is None:
            return None
        if self._cached_paths_event_id != self.current_event_id or self._cached_paths is None:
            self._cached_paths = event_paths(self.data, self.data.events[self.current_event_id])
            self._cached_paths_event_id = self.current_event_id
        return self._cached_paths

    def _current_playback_elapsed(self) -> float:
        if not self._playback_running:
            return self._playback_position_ms or 0.0
        return self._playback_anchor_ms + (
            time.perf_counter() - self._playback_anchor_time
        ) * 1000.0 * self._playback_rate

    def toggle_playback(self) -> None:
        if self._playback_enabled:
            paths = self._paths_for_current_event()
            duration = 0.0 if paths is None else max(
                0.0, paths["active_duration_ms"] + paths["tail_duration_ms"]
            )
            if self._playback_running:
                self._playback_position_ms = min(self._current_playback_elapsed(), duration)
            self._playback_enabled = False
            self._playback_running = False
            self._cancel_playback_job()
            self.play_button.configure(text="▶ Play")
            if self._playback_position_ms is not None:
                self._render_playback_frame()
                self.playback_status_var.set(
                    f"Stopped at {self._playback_position_ms:.0f}/{duration:.0f} ms"
                )
            return
        self._playback_enabled = True
        self._start_playback(restart=False)

    def _start_playback(self, *, restart: bool) -> None:
        paths = self._paths_for_current_event()
        if paths is None:
            return
        duration = max(0.0, paths["active_duration_ms"] + paths["tail_duration_ms"])
        if duration <= 0.0:
            self._playback_enabled = False
            self.play_button.configure(text="▶ Play")
            self.playback_status_var.set("No timed movement")
            return
        if restart or self._playback_position_ms is None or self._playback_position_ms >= duration:
            self._playback_position_ms = 0.0
        self._playback_rate = self._selected_playback_rate()
        self._playback_anchor_ms = self._playback_position_ms
        self._playback_anchor_time = time.perf_counter()
        self._playback_running = True
        self.play_button.configure(text="■ Stop")
        self._playback_tick()

    def _playback_speed_changed(self, _event: Any = None) -> None:
        current = self._current_playback_elapsed()
        self._playback_rate = self._selected_playback_rate()
        if self._playback_running:
            self._playback_anchor_ms = current
            self._playback_anchor_time = time.perf_counter()

    def _playback_tick(self) -> None:
        self._playback_job = None
        if not self._playback_running:
            return
        paths = self._paths_for_current_event()
        if paths is None:
            self._reset_playback()
            return
        duration = max(0.0, paths["active_duration_ms"] + paths["tail_duration_ms"])
        elapsed = self._current_playback_elapsed()
        if duration <= 0.0:
            self._reset_playback()
            return
        if elapsed >= duration:
            if self.loop_var.get():
                elapsed %= duration
                self._playback_anchor_ms = elapsed
                self._playback_anchor_time = time.perf_counter()
            else:
                self._playback_enabled = False
                self._playback_running = False
                self._playback_position_ms = duration
                self.play_button.configure(text="▶ Play")
                self._render_playback_frame()
                return
        self._playback_position_ms = elapsed
        self._render_playback_frame()
        self._playback_job = self.root.after(16, self._playback_tick)

    def _render_playback_frame(self) -> None:
        if self.data is None or self.current_event_id is None or self._playback_position_ms is None:
            return
        paths = self._paths_for_current_event()
        if paths is None:
            return
        event = self.data.events[self.current_event_id]
        duration = max(0.0, paths["active_duration_ms"] + paths["tail_duration_ms"])
        self._draw_paths(event, paths, self._playback_position_ms)
        self._draw_speed(event, paths, self._playback_position_ms)
        mode = "loop" if self.loop_var.get() else "once"
        self.playback_status_var.set(
            f"{self._playback_position_ms:.0f}/{duration:.0f} ms · {self._playback_rate:g}× · {mode}"
        )

    def choose_file(self) -> None:
        if self.loading:
            return
        chosen = filedialog.askopenfilename(
            title="Open ABCurves Capture session",
            filetypes=(("ABCurves session ZIP", "*.zip"), ("All files", "*.*")),
        )
        if chosen:
            self.open_path(Path(chosen))

    def set_status(self, text: str) -> None:
        self.status_var.set(text)

    def open_path(self, path: Path) -> None:
        if self.loading:
            return
        if path.suffix.lower() != ".zip":
            messagebox.showerror(APP_TITLE, "Please choose a .zip submission archive.")
            return
        self._playback_enabled = True
        self._reset_playback()
        self.current_event_id = None
        self.play_button.configure(state="disabled")
        self._cached_paths_event_id = None
        self._cached_paths = None
        self.loading = True
        self.open_button.configure(state="disabled")
        self.set_status("Starting safe load…")
        self.drop_text.set(str(path))

        def progress(message: str) -> None:
            self.root.after(0, self.set_status, message)

        def worker() -> None:
            try:
                loaded = load_session(path, progress)
            except Exception as error:
                self.root.after(0, self._load_failed, error)
            else:
                self.root.after(0, self._load_finished, loaded)

        threading.Thread(target=worker, name="session-loader", daemon=True).start()

    def _load_failed(self, error: Exception) -> None:
        self.loading = False
        self.open_button.configure(state="normal")
        self.play_button.configure(state="disabled")
        self.set_status("Load rejected")
        self.drop_text.set("Archive was not opened. Run the private validator for a full report.")
        messagebox.showerror(APP_TITLE, f"The archive was rejected without extraction.\n\n{error}")

    def _load_finished(self, loaded: SessionData) -> None:
        self.loading = False
        self.open_button.configure(state="normal")
        self.data = loaded
        self._playback_enabled = True
        self._cached_paths_event_id = None
        self._cached_paths = None
        self.play_button.configure(state="normal")
        self.review_store = ManualReviewStore(loaded)
        session_id = str(loaded.manifest.get("session_id"))
        plan_kind = loaded.manifest.get("protocol_plan", {}).get("kind", "unknown")
        self.session_label.configure(text=f"{session_id}  •  {plan_kind}")
        self.set_status(
            f"Loaded {len(loaded.events):,} events / {len(loaded.report_qpc):,} USB reports in {loaded.loaded_seconds:.1f}s"
        )
        self.drop_text.set(
            f"Data-only checks passed for viewed artifacts • SHA-256 {loaded.archive_sha256[:16]}… • no extraction"
        )
        if self.review_store.load_warning:
            messagebox.showwarning(APP_TITLE, self.review_store.load_warning)
        self.apply_filter(select_event=0)

    def _event_matches_filter(self, event_id: int) -> bool:
        assert self.data is not None
        event = self.data.events[event_id]
        choice = self.filter_var.get()
        natural = str(event.get("natural_outcome", ""))
        technical = str(event.get("technical_outcome", "none"))
        review = self.review_store.reviews.get(str(event_id)) if self.review_store else None
        if choice == "Hits":
            return natural in {"hit_click", "hit_dwell"}
        if choice == "Miss clicks":
            return natural == "miss_click"
        if choice == "Timeouts":
            return natural in {"timeout", "challenge_end_timeout"}
        if choice == "Technical":
            return technical != "none"
        if choice == "Reviewed":
            return review is not None
        if choice == "Unreviewed":
            return review is None
        if choice == "Flagged reviews":
            return review is not None and review.get("label") not in {"looks_good", "weird_but_valid_human"}
        return True

    def apply_filter(self, select_event: int | None = None) -> None:
        if self.data is None:
            return
        desired = self.current_event_id if select_event is None else select_event
        self.filtered_ids = [event_id for event_id in range(len(self.data.events)) if self._event_matches_filter(event_id)]
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)
        for event_id in self.filtered_ids:
            event = self.data.events[event_id]
            target = event.get("realized_target", {})
            outcome = event_outcome_label(event)
            review = self.review_store.reviews.get(str(event_id), {}).get("label", "") if self.review_store else ""
            self.tree.insert(
                "", "end", iid=str(event_id),
                values=(
                    event_id,
                    event.get("block_ordinal", ""),
                    target.get("task_type", ""),
                    outcome,
                    f"{event_duration_ms(event, self.data.qpc_frequency):.1f}",
                    review,
                ),
            )
        if not self.filtered_ids:
            self._reset_playback()
            self.current_event_id = None
            self.clear_views("No events match this filter.")
            return
        if desired not in self.filtered_ids:
            desired = self.filtered_ids[0]
        self.select_event(int(desired))

    def _tree_selected(self, _event: Any) -> None:
        selected = self.tree.selection()
        if selected:
            self.show_event(int(selected[0]))

    def select_event(self, event_id: int) -> None:
        if str(event_id) not in self.tree.get_children(""):
            return
        self.tree.selection_set(str(event_id))
        self.tree.focus(str(event_id))
        self.tree.see(str(event_id))
        self.show_event(event_id)

    def select_filtered_position(self, position: int) -> None:
        if not self.filtered_ids:
            return
        position = min(max(position, 0), len(self.filtered_ids) - 1)
        self.select_event(self.filtered_ids[position])

    def navigate(self, delta: int) -> None:
        if not self.filtered_ids:
            return
        try:
            position = self.filtered_ids.index(self.current_event_id) if self.current_event_id is not None else 0
        except ValueError:
            position = 0
        self.select_filtered_position(position + delta)

    def jump_to_event(self) -> None:
        if self.data is None:
            return
        try:
            event_id = int(self.jump_var.get())
        except ValueError:
            return
        if not 0 <= event_id < len(self.data.events):
            messagebox.showinfo(APP_TITLE, f"Event ID must be 0..{len(self.data.events) - 1}.")
            return
        if event_id not in self.filtered_ids:
            self.filter_var.set("All events")
            self.apply_filter(select_event=event_id)
        else:
            self.select_event(event_id)

    def show_event(self, event_id: int) -> None:
        if self.data is None or not 0 <= event_id < len(self.data.events):
            return
        changed = event_id != self.current_event_id
        if changed:
            self._reset_playback()
            self._cached_paths_event_id = None
            self._cached_paths = None
        self.current_event_id = event_id
        self.jump_var.set(str(event_id))
        review = self.review_store.reviews.get(str(event_id)) if self.review_store else None
        self.review_label_var.set(review.get("label", REVIEW_LABELS[0]) if review else REVIEW_LABELS[0])
        self.review_note_var.set(review.get("note", "") if review else "")
        self.review_status_var.set("reviewed" if review else "unreviewed")
        self.redraw()
        if changed and self._playback_enabled:
            self._start_playback(restart=True)

    def schedule_redraw(self, _event: Any = None) -> None:
        if self._redraw_job is not None:
            self.root.after_cancel(self._redraw_job)
        self._redraw_job = self.root.after(80, self.redraw)

    def clear_views(self, message: str = "Open a session to inspect events.") -> None:
        for canvas in (self.path_canvas, self.speed_canvas):
            canvas.delete("all")
            canvas.create_text(
                max(canvas.winfo_width() / 2, 100), max(canvas.winfo_height() / 2, 50),
                text=message, fill=self.COLORS["muted"], font=("Segoe UI", 11),
            )
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", message)
        self.details.configure(state="disabled")

    def redraw(self) -> None:
        self._redraw_job = None
        if self.data is None or self.current_event_id is None:
            self.clear_views()
            return
        event = self.data.events[self.current_event_id]
        paths = self._paths_for_current_event()
        if paths is None:
            self.clear_views()
            return
        self._draw_paths(event, paths, self._playback_position_ms)
        self._draw_speed(event, paths, self._playback_position_ms)
        self._draw_details(event, paths)

    @staticmethod
    def _outcome_color(event: dict[str, Any], colors: dict[str, str]) -> str:
        natural = str(event.get("natural_outcome"))
        if natural.startswith("hit"):
            return colors["hit"]
        if natural == "miss_click":
            return colors["miss"]
        if natural in {"timeout", "challenge_end_timeout"}:
            return colors["timeout"]
        return colors["technical"]

    def _draw_paths(
        self,
        event: dict[str, Any],
        paths: dict[str, Any],
        playback_ms: float | None = None,
    ) -> None:
        canvas = self.path_canvas
        canvas.delete("all")
        width = max(canvas.winfo_width(), 300)
        height = max(canvas.winfo_height(), 250)
        target_x = float(event.get("target_x_counts", 0))
        target_y = float(event.get("target_y_counts", 0))
        radius = float(event.get("target_radius_counts", 1))
        final_camera = event.get("final_camera", {})
        all_points = list(paths["usb"]) + list(paths["raw"]) + [
            (target_x - radius, target_y - radius), (target_x + radius, target_y + radius),
            (float(final_camera.get("x_counts", 0)), float(final_camera.get("y_counts", 0))),
        ]
        minimum_x = min(point[0] for point in all_points)
        maximum_x = max(point[0] for point in all_points)
        minimum_y = min(point[1] for point in all_points)
        maximum_y = max(point[1] for point in all_points)
        span_x = max(maximum_x - minimum_x, 10.0)
        span_y = max(maximum_y - minimum_y, 10.0)
        padding = 48.0
        scale = min((width - 2 * padding) / span_x, (height - 2 * padding) / span_y)
        center_x = (minimum_x + maximum_x) / 2
        center_y = (minimum_y + maximum_y) / 2

        def screen(point: tuple[float, float]) -> tuple[float, float]:
            return (
                width / 2 + (point[0] - center_x) * scale,
                height / 2 - (point[1] - center_y) * scale,
            )

        # Count-space grid anchored around the data center.
        raw_step = max(span_x, span_y) / 8
        magnitude = 10 ** math.floor(math.log10(max(raw_step, 1.0)))
        grid_step = min((1, 2, 5, 10), key=lambda factor: abs(raw_step - factor * magnitude)) * magnitude
        grid_start_x = math.floor(minimum_x / grid_step) * grid_step
        grid_start_y = math.floor(minimum_y / grid_step) * grid_step
        value = grid_start_x
        while value <= maximum_x + grid_step:
            sx, _ = screen((value, center_y))
            canvas.create_line(sx, 28, sx, height - 24, fill=self.COLORS["grid"])
            canvas.create_text(sx + 3, height - 18, text=f"{value:g}", anchor="nw", fill=self.COLORS["muted"], font=("Segoe UI", 7))
            value += grid_step
        value = grid_start_y
        while value <= maximum_y + grid_step:
            _, sy = screen((center_x, value))
            canvas.create_line(32, sy, width - 18, sy, fill=self.COLORS["grid"])
            value += grid_step

        def line(points: list[tuple[float, float]], color: str, width_px: int, dash: tuple[int, int] | None = None) -> None:
            if len(points) < 2:
                return
            coordinates: list[float] = []
            for point in points:
                coordinates.extend(screen(point))
            canvas.create_line(*coordinates, fill=color, width=width_px, smooth=False, dash=dash)

        line(paths["raw"], self.COLORS["raw"], 2, (5, 3))
        line(paths["usb"], self.COLORS["usb"], 2)
        target_screen = screen((target_x, target_y))
        radius_px = max(radius * scale, 3)
        outcome_color = self._outcome_color(event, self.COLORS)
        canvas.create_oval(
            target_screen[0] - radius_px, target_screen[1] - radius_px,
            target_screen[0] + radius_px, target_screen[1] + radius_px,
            outline=outcome_color, width=3,
        )
        if paths["usb"]:
            start_screen = screen(paths["usb"][0])
            canvas.create_line(start_screen[0] - 7, start_screen[1], start_screen[0] + 7, start_screen[1], fill=self.COLORS["text"], width=2)
            canvas.create_line(start_screen[0], start_screen[1] - 7, start_screen[0], start_screen[1] + 7, fill=self.COLORS["text"], width=2)
            end_screen = screen(paths["usb"][-1])
            canvas.create_oval(end_screen[0] - 4, end_screen[1] - 4, end_screen[0] + 4, end_screen[1] + 4, fill=self.COLORS["usb"], outline="")
        if paths["raw"]:
            raw_end = screen(paths["raw"][-1])
            canvas.create_rectangle(raw_end[0] - 4, raw_end[1] - 4, raw_end[0] + 4, raw_end[1] + 4, fill=self.COLORS["raw"], outline="")
        recorded = screen((float(final_camera.get("x_counts", 0)), float(final_camera.get("y_counts", 0))))
        canvas.create_line(recorded[0] - 5, recorded[1] - 5, recorded[0] + 5, recorded[1] + 5, fill="#111111", width=2)
        canvas.create_line(recorded[0] - 5, recorded[1] + 5, recorded[0] + 5, recorded[1] - 5, fill="#111111", width=2)
        for hypothesis in event.get("click_hypotheses", []):
            position = hypothesis.get("post_delta_position", {})
            if isinstance(position, dict):
                click = screen((float(position.get("x_counts", 0)), float(position.get("y_counts", 0))))
                canvas.create_oval(click[0] - 5, click[1] - 5, click[0] + 5, click[1] + 5, outline=self.COLORS["miss"], width=2)
        if playback_ms is not None:
            sample = playback_sample(paths, playback_ms)
            line(sample["trail"], self.COLORS["cursor"], 3)
            cursor_x, cursor_y = screen((sample["x"], sample["y"]))
            radius_px = 5.0
            canvas.create_oval(
                cursor_x - radius_px, cursor_y - radius_px,
                cursor_x + radius_px, cursor_y + radius_px,
                fill="#ffffff", outline=self.COLORS["cursor"], width=3,
            )
            direction_x = float(sample["direction_x"])
            direction_y = -float(sample["direction_y"])  # canonical Y-up -> screen Y-down
            direction_norm = math.hypot(direction_x, direction_y)
            if direction_norm > 0.0:
                arrow_length = 18.0
                arrow_x = cursor_x + direction_x / direction_norm * arrow_length
                arrow_y = cursor_y + direction_y / direction_norm * arrow_length
                canvas.create_line(
                    cursor_x, cursor_y, arrow_x, arrow_y,
                    fill=self.COLORS["cursor"], width=3, arrow="last", arrowshape=(7, 8, 3),
                )
        title = f"Event {event.get('event_id')} • canonical count space (Y up)"
        if playback_ms is not None:
            title += f" • playback {playback_ms:.0f} ms"
        canvas.create_text(12, 10, anchor="nw", text=title, fill=self.COLORS["text"], font=("Segoe UI", 11, "bold"))
        canvas.create_text(
            width - 12, 10, anchor="ne",
            text="USB authoritative  ━━━    Raw witness  ┄┄┄    playback cursor  ●➜",
            fill=self.COLORS["muted"], font=("Segoe UI", 9),
        )

    def _draw_speed(
        self,
        event: dict[str, Any],
        paths: dict[str, Any],
        playback_ms: float | None = None,
    ) -> None:
        canvas = self.speed_canvas
        canvas.delete("all")
        width = max(canvas.winfo_width(), 300)
        height = max(canvas.winfo_height(), 140)
        padding_left, padding_right, padding_top, padding_bottom = 45, 18, 25, 30
        speeds = paths["speed"]
        maximum_time = max((value[0] for value in speeds), default=1.0)
        maximum_speed = max((value[1] for value in speeds), default=1.0)
        maximum_time = max(maximum_time, paths["active_duration_ms"] + paths["tail_duration_ms"], 1.0)
        maximum_speed = max(maximum_speed, 1.0)

        def sx(milliseconds: float) -> float:
            return padding_left + milliseconds / maximum_time * (width - padding_left - padding_right)

        def sy(speed: float) -> float:
            return height - padding_bottom - speed / maximum_speed * (height - padding_top - padding_bottom)

        for fraction in (0.0, 0.25, 0.5, 0.75, 1.0):
            y = padding_top + fraction * (height - padding_top - padding_bottom)
            canvas.create_line(padding_left, y, width - padding_right, y, fill=self.COLORS["grid"])
        canvas.create_line(padding_left, height - padding_bottom, width - padding_right, height - padding_bottom, fill=self.COLORS["muted"])
        if len(speeds) >= 2:
            coordinates: list[float] = []
            for milliseconds, speed in speeds:
                coordinates.extend((sx(milliseconds), sy(speed)))
            canvas.create_line(*coordinates, fill=self.COLORS["usb"], width=2)
        resolution_x = sx(paths["active_duration_ms"])
        canvas.create_line(resolution_x, padding_top, resolution_x, height - padding_bottom, fill=self._outcome_color(event, self.COLORS), width=2, dash=(4, 3))
        for click in event.get("click_hypotheses", []):
            qpc = click.get("qpc")
            if isinstance(qpc, int):
                milliseconds = (qpc - event_start_qpc(event)) * 1000.0 / (self.data.qpc_frequency if self.data else 1)
                x = sx(milliseconds)
                canvas.create_line(x, padding_top, x, height - padding_bottom, fill=self.COLORS["miss"], width=1)
        if playback_ms is not None:
            playback_x = sx(min(max(playback_ms, 0.0), maximum_time))
            canvas.create_line(
                playback_x, padding_top, playback_x, height - padding_bottom,
                fill=self.COLORS["cursor"], width=2,
            )
            canvas.create_text(
                playback_x + 3, height - padding_bottom - 3,
                anchor="sw", text=f"{playback_ms:.0f} ms",
                fill=self.COLORS["cursor"], font=("Segoe UI", 8, "bold"),
            )
        canvas.create_text(10, 8, anchor="nw", text="USB motion magnitude / 4 ms bin", fill=self.COLORS["text"], font=("Segoe UI", 9, "bold"))
        canvas.create_text(padding_left, height - 7, anchor="sw", text="0 ms", fill=self.COLORS["muted"], font=("Segoe UI", 8))
        canvas.create_text(width - padding_right, height - 7, anchor="se", text=f"{maximum_time:.0f} ms", fill=self.COLORS["muted"], font=("Segoe UI", 8))
        canvas.create_text(resolution_x + 3, padding_top, anchor="nw", text="resolution", fill=self._outcome_color(event, self.COLORS), font=("Segoe UI", 8))

    def _draw_details(self, event: dict[str, Any], paths: dict[str, Any]) -> None:
        assert self.data is not None
        target = event.get("realized_target", {})
        render = event.get("render_evidence", {})
        final_camera = event.get("final_camera", {})
        usb_end = paths["usb"][-1] if paths["usb"] else (0.0, 0.0)
        raw_end = paths["raw"][-1] if paths["raw"] else None
        final_x = float(final_camera.get("x_counts", 0))
        final_y = float(final_camera.get("y_counts", 0))
        lines = [
            f"SESSION  {self.data.manifest.get('session_id')}",
            f"EVENT    {event.get('event_id')}  block {event.get('block_ordinal')} / target {event.get('target_ordinal_in_block')}",
            f"TASK     {target.get('task_type')} ({target.get('challenge_id')})",
            f"OUTCOME  natural={event.get('natural_outcome')}  technical={event.get('technical_outcome')}",
            f"TIMING   active={paths['active_duration_ms']:.3f} ms  tail={paths['tail_duration_ms']:.3f} ms",
            f"INPUT    USB reports={paths['usb_report_count']:,}  Raw Input packets={paths['raw_packet_count']:,}",
            "",
            f"TARGET   ({float(event.get('target_x_counts', 0)):.3f}, {float(event.get('target_y_counts', 0)):.3f})  r={event.get('target_radius_counts')}",
            f"DISTANCE initial={float(event.get('initial_distance_counts', 0)):.3f}  closest={float(event.get('closest_swept_distance_counts', 0)):.3f}",
            f"INSIDE   total={float(event.get('inside_total_ms', 0)):.3f} ms  max-run={float(event.get('maximum_consecutive_inside_ms', 0)):.3f} ms",
            f"CLICKS   {len(event.get('click_hypotheses', []))}  scored={event.get('scored')}  score-after={event.get('score_after_event')}",
            "",
            f"FINAL    recorded=({final_x:.0f}, {final_y:.0f})",
            f"         USB integrated=({usb_end[0]:.0f}, {usb_end[1]:.0f})  error={math.hypot(usb_end[0] - final_x, usb_end[1] - final_y):.3f}",
        ]
        if raw_end is not None:
            lines.append(f"         Raw witness=({raw_end[0]:.0f}, {raw_end[1]:.0f})  error={math.hypot(raw_end[0] - final_x, raw_end[1] - final_y):.3f}")
        lines.extend([
            "",
            f"VIEWPORT {render.get('viewport_width_px')}×{render.get('viewport_height_px')}  fullscreen={render.get('fullscreen')}",
            f"SCALE    {float(render.get('pixels_per_count_x', 0)):.6f} px/count  sensitivity={event.get('trainer_sensitivity')}",
            f"RNG      draws {target.get('rng_draw_begin_u64')}..{target.get('rng_draw_end_u64')}",
        ])
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", "\n".join(lines))
        self.details.configure(state="disabled")

    def save_review(self) -> None:
        if self.review_store is None or self.current_event_id is None:
            return
        try:
            self.review_store.set(
                self.current_event_id, self.review_label_var.get(), self.review_note_var.get().strip()
            )
        except (OSError, ValueError) as error:
            messagebox.showerror(APP_TITLE, f"Could not save review sidecar:\n\n{error}")
            return
        self.review_status_var.set(f"saved → {self.review_store.path.name}")
        self.apply_filter(select_event=self.current_event_id)

    def clear_review(self) -> None:
        if self.review_store is None or self.current_event_id is None:
            return
        try:
            self.review_store.clear(self.current_event_id)
        except OSError as error:
            messagebox.showerror(APP_TITLE, f"Could not save review sidecar:\n\n{error}")
            return
        self.review_label_var.set(REVIEW_LABELS[0])
        self.review_note_var.set("")
        self.review_status_var.set("cleared")
        self.apply_filter(select_event=self.current_event_id)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manual extraction-free viewer for ABCurves Capture session ZIPs")
    parser.add_argument("session", nargs="?", type=Path, help="optional _SEND_THIS.zip to open immediately")
    parser.add_argument("--check", action="store_true", help="validate/load viewed artifacts without opening the UI")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.check:
        if arguments.session is None:
            print("--check requires a session ZIP", file=sys.stderr)
            return 2
        try:
            data = load_session(arguments.session, lambda message: print(message, file=sys.stderr))
        except Exception as error:
            print(f"REJECT: {error}", file=sys.stderr)
            return 1
        outcomes = Counter(event_outcome_label(event) for event in data.events)
        print(json.dumps({
            "session_id": data.manifest.get("session_id"),
            "archive_sha256": data.archive_sha256,
            "events": len(data.events),
            "usb_reports": len(data.report_qpc),
            "raw_input_witness_packets": len(data.raw_qpc),
            "outcomes": dict(sorted(outcomes.items())),
            "loaded_seconds": data.loaded_seconds,
            "no_extraction": True,
        }, indent=2))
        return 0
    root = tk.Tk()
    InspectorApp(root, arguments.session)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
