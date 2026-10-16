#!/usr/bin/env python3
"""Raw UART capture for the DECT NR+ sniffer, decoded offline.

Usage:
  raw_capture_check.py capture <serial-port> <baud> <seconds> <out.bin> [channel] [network-id]
  raw_capture_check.py check <out.bin>

capture: starts the target and stores the raw bytes without decoding them, so
         the serial reader is not slowed down by Wireshark or the pcap writer.
check:   decodes the raw file offline and prints CRC errors and sequence gaps.
         Run it after capture; the result is the reference for the live extcap.

Copyright (c) 2026 Deveritec GmbH - SPDX-License-Identifier: Apache-2.0
"""

import os
import struct
import sys
import time

# Keep this file next to dectnrp_sniffer_extcap.py (same folder).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dectnrp_sniffer_extcap as ex  # noqa: E402


def capture(
    port_name, baud, seconds, out, channel=1677, network_id=ex.DEFAULT_NETWORK_ID
):
    port = ex._open_serial(port_name, baud)
    raw = bytearray()
    try:
        port.write(
            ex.encode_frame(
                ex.FT_CMD,
                bytes([ex.CMD_SET_CONFIG]) + struct.pack("<HI", channel, network_id),
            )
        )
        time.sleep(0.2)
        port.write(ex.encode_frame(ex.FT_CMD, bytes([ex.CMD_START])))
        t_end = time.time() + seconds
        while time.time() < t_end:
            raw += port.read(65536)
        port.write(ex.encode_frame(ex.FT_CMD, bytes([ex.CMD_STOP])))
        t_end = time.time() + 1.0
        while time.time() < t_end:
            raw += port.read(65536)
    finally:
        port.close()
    with open(out, "wb") as fp:
        fp.write(raw)
    print(f"stored {len(raw)} bytes in {out}")


def check(path):
    data = open(path, "rb").read()
    dec = ex.FrameDecoder()
    gaps = ex.SeqGapTracker()
    frames = 0
    for ftype, payload in dec.feed(data):
        if ftype == ex.FT_DATA:
            frames += 1
            gaps.add(payload)
    print(
        f"bytes: {len(data)}, valid DATA frames: {frames}, CRC errors: {dec.crc_errors}"
    )
    print(f"sequence: {gaps.summary()}")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "capture" and len(sys.argv) >= 6:
        ch = int(sys.argv[6]) if len(sys.argv) > 6 else ex.DEFAULT_CHANNEL
        nid = int(sys.argv[7], 0) if len(sys.argv) > 7 else ex.DEFAULT_NETWORK_ID
        capture(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), sys.argv[5], ch, nid)
    elif len(sys.argv) == 3 and sys.argv[1] == "check":
        check(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(2)
