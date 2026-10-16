#!/usr/bin/env python3
"""
DECT NR+ sniffer - DEBUG extcap (no hardware, no serial port).

Writes a continuous stream of DECT-NR-TAP records into the Wireshark FIFO
(LINKTYPE_DECT_NR_TAP = 304). Two payload modes (option --frames):

  mac     (default) Valid MAC frames: Network Beacon, Association Request and
          Association Response. Each record carries the PHY control field (PCC),
          the MAC common header, the MUX header and, where the spec requires it,
          the RD Capability IE. Bit layouts follow ETSI TS 103 636-4 V2.2.1.
  random  Random PCC/PDC bytes, changing PHY type, PDC CRC errors and RSSI/SNR.
          Only the TAP header is meaningful. Use it to test the TAP dissector.

Use it to check the Wireshark setup and the dissectors without the nRF9151 DK.
The TAP header and TLV layout is the same as src/sniffer_codec.c.

Requires dectnrp_sniffer_extcap.py in the same directory.
Copyright (c) 2026 Deveritec GmbH - SPDX-License-Identifier: Apache-2.0
"""

import argparse
import math
import os
import random
import signal
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dectnrp_sniffer_extcap import (  # noqa: E402
    DLT_DECT_NR_TAP,
    DLT_DISPLAY,
    DLT_NAME,
    PcapWriter,
    VERSION,
)

INTERFACE_ID = "dectnrp-sniffer-debug"
INTERFACE_DISPLAY = "DECT NR+ Sniffer - DEBUG generator (no hardware)"
DEFAULT_CHANNEL = 1677
DEFAULT_INTERVAL_MS = 200
DEFAULT_SPAN = 4
DEFAULT_SEED = 1
DEFAULT_FRAMES = "mac"
FRAME_MODES = ("mac", "random")
FRAME_MAC = "mac"
FRAME_RANDOM = "random"
PDC_ABSENT_EVERY = 7  # random mode: every 7th record simulates a PDC CRC error
TAP_MIN_TLVS = 8  # reference dissector rejects shorter records

# TAP metadata entry types (src/sniffer_codec.h)
TLV_PAD = 0
TLV_DATA_TYPE = 1
TLV_HEADER_STATUS = 2
TLV_PCC_RSSI2 = 3
TLV_PCC_SNR = 4
TLV_PDC_RSSI2 = 5
TLV_PDC_SNR = 6
TLV_TRANSACTION_ID = 7
TLV_CHANNEL = 8


def _tlv(typ, value=0, value_len=2):
    """One 8-byte entry: type (2), length of value (2), value (2), padding (2)."""
    return struct.pack(
        "<HHHH", typ, value_len, (value & 0xFFFF) if value_len == 2 else 0, 0
    )


def build_tap_record(channel, seq, phy_type, pcc_pdc, pdc_len, metrics=None):
    """DECT-NR-TAP record. Same layout as sniff_build_tap_record() in src/sniffer_codec.c.

    phy_type 0 = PCC Type 1 (5 bytes), 1 = PCC Type 2 (10 bytes).
    metrics is None or (pcc_rssi2, pcc_snr, pdc_rssi2, pdc_snr) as raw signed values.
    """
    pcc_len = 5 if phy_type == 0 else 10
    body = pcc_len + pdc_len
    if len(pcc_pdc) != body:
        raise ValueError("pcc_pdc must hold pcc_len + pdc_len bytes")
    if pdc_len > 0:
        data_type, header_status = (1 if phy_type == 0 else 2), 0
    else:
        data_type, header_status = (3 if phy_type == 0 else 4), 2

    entries = [
        (TLV_DATA_TYPE, data_type),
        (TLV_HEADER_STATUS, header_status),
        (TLV_TRANSACTION_ID, seq & 0xFFFF),
        (TLV_CHANNEL, channel),
    ]
    if metrics is not None:
        pcc_rssi2, pcc_snr, pdc_rssi2, pdc_snr = metrics
        entries += [
            (TLV_PCC_RSSI2, pcc_rssi2),
            (TLV_PCC_SNR, pcc_snr),
            (TLV_PDC_RSSI2, pdc_rssi2),
            (TLV_PDC_SNR, pdc_snr),
        ]
    while len(entries) < TAP_MIN_TLVS:
        entries.append(None)

    tlv_bytes = b"".join(
        _tlv(*e) if e is not None else _tlv(TLV_PAD, 0, 0) for e in entries
    )
    # Header: version 1, reserved 0, TLV chain length in bytes, modem length, reserved 0
    header = bytes([1, 0]) + struct.pack("<HHH", len(entries) * 8, body, 0)
    return header + tlv_bytes + bytes(pcc_pdc)


# ---- valid MAC frames ---------------------------------------------------------
# Bit layouts from ETSI TS 103 636-4 V2.2.1: PHY control field Type 1 (Table
# 6.2.1-1), Type 2 (Tables 6.2.1-2 and 6.2.1-2a), MAC header types (6.3.2, 6.3.3),
# MUX header (6.3.4), Network Beacon, Association Request and Association Response
# (6.4.2.2, 6.4.2.4, 6.4.2.5) and RD Capability IE (6.4.3.5). All fields MSB first.
# The Wireshark dissector packet-dect-nr.c was used as cross-check for offsets.

MAC_KINDS = ("network_beacon", "association_request", "association_response")

# Demo network: one FT RD (sends beacons) and one PT RD (associates).
NETWORK_ID = 0x1A2B3C4D  # 32 bit. Short NW ID = LSB, clause 4.2.3.1
FT_LONG_RD_ID = 0x0A1B2C3D  # 32 bit Long RD ID of the FT RD
FT_SHORT_RD_ID = 0x2C3D  # 16 bit Short RD ID of the FT RD
PT_LONG_RD_ID = 0x5E6F7A8B  # Long RD ID of the PT RD
PT_SHORT_RD_ID = 0x7A8B  # Short RD ID of the PT RD
PKT_LEN_CODE = 3  # packet length code 3 = 4 subslots (nominal, not from PDU size)
TX_POWER_UNICAST = 4  # Table 6.2.1-3a: -12 dBm
TX_POWER_BEACON = 5  # Table 6.2.1-3a: -8 dBm
MCS_BEACON = 0  # BPSK
MCS_UNICAST = 1  # QPSK, R=1/2

MAC_HDR_BEACON = 0b0001  # MAC header type field, Table 6.3.2-2
MAC_HDR_UNICAST = 0b0010
MUX_EXT_LEN8 = 0b01  # MAC extension 01: 8 bit length after the IE type
IE_NETWORK_BEACON = 0b001000  # Table 6.3.4-2
IE_ASSOC_REQUEST = 0b001010
IE_ASSOC_RESPONSE = 0b001011
IE_RD_CAPABILITY = 0b010100
FLOW_USER_PLANE_1 = 0b000011
NB_PERIOD_500_MS = 2  # Table 6.4.2.2-1 coded values
CB_PERIOD_100_MS = 2
CLUSTER_MAX_TX_CODE = 5  # Table 6.2.1-3b: -8 dBm
HARQ_RE_TX_1_MS = 4  # Table 6.4.2.4-1 coded values: 1 ms


def _pack_bits(fields):
    """Pack (value, width) pairs MSB first. The total width must fill whole octets."""
    acc = 0
    total = 0
    for value, width in fields:
        if not 0 <= value < (1 << width):
            raise ValueError(f"value {value} does not fit in {width} bits")
        acc = (acc << width) | value
        total += width
    if total % 8:
        raise ValueError("fields must fill whole octets")
    return acc.to_bytes(total // 8, "big")


def phy_control_type1(tx_short, nw_short, tx_power, mcs):
    """PCC Type 1, header format 000, 40 bits (Table 6.2.1-1)."""
    return _pack_bits(
        [
            (0b000, 3),
            (0, 1),
            (PKT_LEN_CODE, 4),
            (nw_short, 8),
            (tx_short, 16),
            (tx_power, 4),
            (0, 1),
            (mcs, 3),
        ]
    )


def phy_control_type2(
    fmt,
    tx_short,
    rx_short,
    nw_short,
    tx_power,
    mcs,
    nss,
    fb_format,
    fb_info,
    rv=0,
    ndi=0,
    harq=0,
):
    """PCC Type 2, 80 bits. fmt 0 = header format 000 (Table 6.2.1-2),
    fmt 1 = header format 001 (Table 6.2.1-2a, 6 reserved bits instead of RV/NDI/HARQ)."""
    if fmt == 0:
        middle = [(rv, 2), (ndi, 1), (harq, 3)]
    else:
        middle = [(0, 6)]
    return _pack_bits(
        [
            (fmt, 3),
            (0, 1),
            (PKT_LEN_CODE, 4),
            (nw_short, 8),
            (tx_short, 16),
            (tx_power, 4),
            (mcs, 4),
            (rx_short, 16),
            (nss, 2),
        ]
        + middle
        + [(fb_format, 4), (fb_info, 12)]
    )


def mac_beacon_header(nw_id, tx_long):
    """Beacon Header (6.3.3.2): header type byte, 24 MSB of Network ID, Long RD ID of sender."""
    return (
        bytes([MAC_HDR_BEACON])
        + (nw_id >> 8).to_bytes(3, "big")
        + tx_long.to_bytes(4, "big")
    )


def mac_unicast_header(sn, reset, rx_long, tx_long):
    """Unicast Header (6.3.3.3): header type byte, 2 reserved bits, DWA (0),
    reset bit, 12 bit sequence number, Rx and Tx Long RD IDs."""
    return (
        bytes([MAC_HDR_UNICAST])
        + _pack_bits([(0, 2), (0, 1), (reset, 1), (sn & 0xFFF, 12)])
        + rx_long.to_bytes(4, "big")
        + tx_long.to_bytes(4, "big")
    )


def mux_ie(ie_type, payload):
    """MUX header (6.3.4) with MAC extension 01 (8 bit length), then the IE payload."""
    if len(payload) > 255:
        raise ValueError("IE payload too long for an 8 bit length field")
    return bytes([(MUX_EXT_LEN8 << 6) | ie_type, len(payload)]) + payload


def network_beacon_ie(channel, time_to_next_us):
    """Network Beacon IE (Table 6.4.2.2-1), 11 bytes. TX power and current cluster
    channel fields are included, no additional network beacon channels."""
    return _pack_bits(
        [
            (0, 3),
            (1, 1),
            (0, 1),
            (1, 1),
            (0, 2),  # reserved, TX power incl., power const, current incl., NB channels
            (NB_PERIOD_500_MS, 4),
            (CB_PERIOD_100_MS, 4),
            (0, 3),
            (channel, 13),  # next cluster channel
            (time_to_next_us, 32),  # time to next cluster beacon period [us]
            (0, 4),
            (CLUSTER_MAX_TX_CODE, 4),  # clusters max TX power
            (0, 3),
            (channel, 13),  # current cluster channel
        ]
    )


def association_request_ie(flow_ids, setup_cause=0):
    """Association Request IE (Table 6.4.2.4-1). PT only (FT mode 0), so the
    beacon period, next channel and time fields are absent."""
    fields = [
        (setup_cause, 3),
        (len(flow_ids), 3),
        (0, 1),
        (0, 1),  # setup cause, flows, power const, FT mode
        (0, 1),
        (0, 7),  # current, reserved
        (1, 3),
        (HARQ_RE_TX_1_MS, 5),  # HARQ processes TX, max HARQ re-TX
        (1, 3),
        (HARQ_RE_TX_1_MS, 5),
    ]  # HARQ processes RX, max HARQ re-RX
    for flow_id in flow_ids:
        fields += [(0, 2), (flow_id, 6)]  # reserved, flow ID
    return _pack_bits(fields)


def association_response_ie():
    """Association Response IE (Table 6.4.2.5-1) accepting the request: ACK=1,
    HARQ as requested, number of flows 111 (all flows accepted), no group assignment."""
    return _pack_bits([(1, 1), (0, 1), (0, 1), (0b111, 3), (0, 1), (0, 1)])


def rd_capability_ie(op_mode):
    """RD Capability IE (6.4.3.5) with no additional PHY capabilities, 7 bytes.
    op_mode: 0 = PT mode only, 2 = PT and FT modes."""
    return _pack_bits(
        [
            (0, 3),
            (2, 5),  # number of PHY capabilities 0, release 2
            (0, 2),
            (0, 1),
            (0, 1),
            (op_mode, 2),
            (0, 1),
            (0, 1),  # reserved, group ass., paging, op. modes, mesh, scheduled
            (0, 3),
            (4, 3),
            (0, 2),  # MAC security not supported, DLC service types 0-3, reserved
            (0, 1),
            (2, 3),
            (0, 2),
            (0, 2),  # reserved, power class III, max NSS RX 1, RX for TX diversity 1
            (5, 4),
            (4, 4),  # RX gain 0 dB, max MCS 16-QAM R=3/4
            (3, 4),
            (2, 2),
            (0, 2),  # soft buffer 64 000 B, 4 HARQ processes, reserved
            (1, 4),
            (0, 1),
            (0, 1),
            (0, 2),  # HARQ feedback delay 1 subslot, D_delay, half duplex, reserved
        ]
    )


def build_mac_frame(kind, seq, channel):
    """One valid frame as (phy_type, PCC + PDU bytes, PDU length).
    phy_type 0 = PCC Type 1, 1 = PCC Type 2. Beacon messages use PCC Type 1, all other
    messages PCC Type 2 with the receiver's Short RD ID (as required by the spec)."""
    sn = seq & 0xFFF
    ch = channel & 0x1FFF  # channel fields are 13 bits wide
    nw_short = NETWORK_ID & 0xFF
    if kind == "network_beacon":
        pcc = phy_control_type1(FT_SHORT_RD_ID, nw_short, TX_POWER_BEACON, MCS_BEACON)
        time_to_next = 100_000 - (seq % 10) * 10_000  # 10 .. 100 ms
        pdu = mac_beacon_header(NETWORK_ID, FT_LONG_RD_ID) + mux_ie(
            IE_NETWORK_BEACON, network_beacon_ie(ch, time_to_next)
        )
        phy_type = 0
    elif kind == "association_request":
        pcc = phy_control_type2(
            0,
            PT_SHORT_RD_ID,
            FT_SHORT_RD_ID,
            nw_short,
            TX_POWER_UNICAST,
            MCS_UNICAST,
            nss=0,
            fb_format=0,
            fb_info=0,
            ndi=seq & 1,
        )
        pdu = (
            mac_unicast_header(sn, 1, FT_LONG_RD_ID, PT_LONG_RD_ID)
            + mux_ie(IE_ASSOC_REQUEST, association_request_ie([FLOW_USER_PLANE_1]))
            + mux_ie(IE_RD_CAPABILITY, rd_capability_ie(op_mode=0))
        )
        phy_type = 1
    elif kind == "association_response":
        pcc = phy_control_type2(
            1,
            FT_SHORT_RD_ID,
            PT_SHORT_RD_ID,
            nw_short,
            TX_POWER_UNICAST,
            MCS_UNICAST,
            nss=0,
            fb_format=0,
            fb_info=0,
        )
        pdu = (
            mac_unicast_header(sn, 1, PT_LONG_RD_ID, FT_LONG_RD_ID)
            + mux_ie(IE_ASSOC_RESPONSE, association_response_ie())
            + mux_ie(IE_RD_CAPABILITY, rd_capability_ie(op_mode=2))
        )
        phy_type = 1
    else:
        raise ValueError(f"unknown frame kind: {kind}")
    return phy_type, pcc + pdu, len(pdu)


# ---- record source ------------------------------------------------------------


class DummySource:
    """Produces the debug records. Deterministic for a given seed and payload mode."""

    def __init__(
        self,
        base_channel=DEFAULT_CHANNEL,
        span=DEFAULT_SPAN,
        seed=DEFAULT_SEED,
        with_metrics=True,
        payload=FRAME_RANDOM,
    ):
        self.base_channel = base_channel
        self.span = span
        self.with_metrics = with_metrics
        self.payload = payload
        self._rng = random.Random(seed)

    def _random_payload(self, i):
        phy_type = (i // 5) % 2  # switches every 5 records
        pdc_absent = (i % PDC_ABSENT_EVERY) == PDC_ABSENT_EVERY - 1
        pdc_len = 0 if pdc_absent else 16 + (i * 37) % 200
        pcc_len = 5 if phy_type == 0 else 10
        pcc_pdc = bytes(self._rng.getrandbits(8) for _ in range(pcc_len + pdc_len))
        return phy_type, pcc_pdc, pdc_len, pdc_absent

    def record(self, i):
        channel = (self.base_channel + i % self.span) % 65536
        if self.payload == FRAME_MAC:
            kind = MAC_KINDS[i % len(MAC_KINDS)]
            phy_type, pcc_pdc, pdc_len = build_mac_frame(kind, i, channel)
            pdc_absent = False
        else:
            phy_type, pcc_pdc, pdc_len, pdc_absent = self._random_payload(i)

        metrics = None
        if self.with_metrics:
            t = i * 0.05
            pcc_dbm = -65.0 - 10.0 * (1.0 + math.sin(t))  # -65 .. -85 dBm
            pcc_snr = 12.0 + 6.0 * math.sin(t * 1.7)  # 6 .. 18 dB
            pcc = (round(pcc_dbm * 2), round(pcc_snr * 4))  # Q14.1 / Q13.2
            if pdc_absent:
                pdc = (0, 0)
            else:
                pdc = (round((pcc_dbm - 2.0) * 2), round((pcc_snr - 1.5) * 4))
            metrics = (pcc[0], pcc[1], pdc[0], pdc[1])
        return build_tap_record(
            channel, i & 0xFFFF, phy_type, pcc_pdc, pdc_len, metrics
        )


def run_generator(fifo, source, interval_s, count, log, stop_event):
    """Write records until stopped, count records were written, or the pipe closes."""
    pcap = PcapWriter(fifo)
    written = 0
    try:
        while not stop_event.is_set() and (count == 0 or written < count):
            pcap.write_packet(time.time_ns(), source.record(written))
            written += 1
            if written % 100 == 0:
                log(f"{written} debug records written")
            if stop_event.wait(interval_s):
                break
    except BrokenPipeError:
        log("Wireshark closed the capture pipe")
    finally:
        log(f"stopped after {written} debug records")


# ---- extcap queries -----------------------------------------------------------


def _extcap_interfaces():
    print(
        f"extcap {{version={VERSION}}}{{help=https://github.com/Opener-Initiative/opener-samples}}"
    )
    print(f"interface {{value={INTERFACE_ID}}}{{display={INTERFACE_DISPLAY}}}")
    print(f"version {{interface={INTERFACE_ID}}}{{version={VERSION}}}")


def _extcap_dlts():
    print(
        f"dlt {{number={DLT_DECT_NR_TAP}}}{{name={DLT_NAME}}}{{display={DLT_DISPLAY}}}"
    )


def _extcap_config():
    print(
        f"arg {{number=0}}{{call=--interval-ms}}{{display=Interval}}{{type=unsigned}}"
        f"{{range=10,10000}}{{default={DEFAULT_INTERVAL_MS}}}"
        "{tooltip=Time between two debug records in milliseconds}"
    )
    print(
        f"arg {{number=1}}{{call=--channel}}{{display=DECT NR+ channel}}{{type=unsigned}}"
        f"{{range=0,65535}}{{default={DEFAULT_CHANNEL}}}"
        "{tooltip=First channel of the debug cycle}"
    )
    print(
        f"arg {{number=2}}{{call=--channel-span}}{{display=Channels in cycle}}{{type=unsigned}}"
        f"{{range=1,16}}{{default={DEFAULT_SPAN}}}"
        "{tooltip=Records cycle through this many channels, starting at the first channel}"
    )
    print(
        "arg {number=3}{call=--metrics}{display=RSSI / SNR}{type=selector}"
        "{tooltip=Include PCC/PDC RSSI and SNR in the records}"
    )
    print("value {arg=3}{value=on}{display=Include}{default=true}")
    print(
        "value {arg=3}{value=off}{display=Omit (as the target does today)}{default=false}"
    )
    print(
        "arg {number=4}{call=--frames}{display=Frame content}{type=selector}"
        "{tooltip=Valid MAC frames (beacon, association request and response) or random payload}"
    )
    print("value {arg=4}{value=mac}{display=Valid MAC frames}{default=true}")
    print(
        "value {arg=4}{value=random}{display=Random payload (TAP format test)}{default=false}"
    )


# ---- command line -------------------------------------------------------------


def _parse_int(text, lo, hi, name):
    value = int(str(text), 0)
    if not lo <= value <= hi:
        raise ValueError(f"{name} out of range: {value}")
    return value


def parse_args(argv):
    p = argparse.ArgumentParser(
        description="DECT NR+ sniffer DEBUG extcap (no hardware)", allow_abbrev=False
    )
    p.add_argument("--extcap-interfaces", action="store_true")
    p.add_argument("--extcap-interface", default=INTERFACE_ID)
    p.add_argument("--extcap-dlts", action="store_true")
    p.add_argument("--extcap-config", action="store_true")
    p.add_argument("--extcap-version", nargs="?", const="", default=None)
    p.add_argument("--extcap-capture-filter", default=None)
    p.add_argument("--capture", action="store_true")
    p.add_argument("--fifo", default=None)
    p.add_argument("--interval-ms", default=str(DEFAULT_INTERVAL_MS))
    p.add_argument("--channel", default=str(DEFAULT_CHANNEL))
    p.add_argument("--channel-span", default=str(DEFAULT_SPAN))
    p.add_argument("--metrics", default="on")
    p.add_argument(
        "--frames", default=DEFAULT_FRAMES, help="'mac' (valid MAC frames) or 'random'"
    )
    p.add_argument("--seed", default=str(DEFAULT_SEED))
    p.add_argument(
        "--count", default="0", help="stop after N records (0 = until stopped)"
    )
    args, _unknown = p.parse_known_args(argv)
    return args


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)

    def log(msg):
        print(f"[dectnrp-sniffer-debug] {msg}", file=sys.stderr, flush=True)

    if args.extcap_interfaces or (args.extcap_version is not None and not args.capture):
        _extcap_interfaces()
        return 0
    if args.extcap_dlts:
        _extcap_dlts()
        return 0
    if args.extcap_config:
        _extcap_config()
        return 0
    if not args.capture:
        log("nothing to do: use --capture together with --fifo")
        return 1
    if not args.fifo:
        log("--fifo is required for --capture")
        return 1

    try:
        interval_ms = _parse_int(args.interval_ms, 10, 10000, "interval-ms")
        channel = _parse_int(args.channel, 0, 65535, "channel")
        span = _parse_int(args.channel_span, 1, 16, "channel-span")
        seed = _parse_int(args.seed, 0, 0xFFFFFFFF, "seed")
        count = _parse_int(args.count, 0, 0x7FFFFFFF, "count")
        if args.metrics not in ("on", "off"):
            raise ValueError("metrics must be 'on' or 'off'")
        if args.frames not in FRAME_MODES:
            raise ValueError("frames must be 'mac' or 'random'")
    except ValueError as exc:
        log(f"invalid option: {exc}")
        return 1

    stop_event = threading.Event()

    def on_signal(_signum, _frame):
        stop_event.set()

    for name in ("SIGTERM", "SIGINT", "SIGHUP", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, on_signal)
            except (ValueError, OSError):
                pass

    source = DummySource(
        channel, span, seed, with_metrics=(args.metrics == "on"), payload=args.frames
    )
    what = (
        "valid MAC frames (beacon, association request/response)"
        if args.frames == FRAME_MAC
        else "random dummy records"
    )
    log(
        f"generating {what}: channel {channel} (cycle of {span}), "
        f"interval {interval_ms} ms, RSSI/SNR {args.metrics}, no hardware"
    )
    try:
        with open(args.fifo, "wb", buffering=0) as fifo:
            run_generator(fifo, source, interval_ms / 1000.0, count, log, stop_event)
    except Exception as exc:  # noqa: BLE001 - report to Wireshark log, exit non-zero
        log(f"capture failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
