#!/usr/bin/env python3
"""
DECT NR+ sniffer - Wireshark extcap for the Opener "dectnrp-sniffer" sample.

The target streams DECT-NR-TAP records (LINKTYPE_DECT_NR_TAP = 304, see
DSRCorporation/dect-nr-tap) over UART. This program:

  * answers Wireshark's extcap queries (--extcap-interfaces, --extcap-dlts,
    --extcap-config),
  * during --capture, configures the target (channel, network ID), starts RX,
    writes a pcap stream with linktype 304 into the Wireshark FIFO, and
    stops the target again on SIGTERM/SIGINT or when Wireshark closes the FIFO.

Requires: Python 3.8+ and the pyserial package (see README).

Copyright (c) 2026 Deveritec GmbH - SPDX-License-Identifier: Apache-2.0
"""

import argparse
import queue
import signal
import struct
import sys
import threading
import time

VERSION = "1.0.0"
INTERFACE_ID = "dectnrp-sniffer"
INTERFACE_DISPLAY = "DECT NR+ Sniffer (Opener)"
DLT_DECT_NR_TAP = 304
DLT_NAME = "DECT_NR_TAP"
DLT_DISPLAY = "DECT NR+ TAP"
DEFAULT_PORT = "/dev/ttyACM0"
DEFAULT_BAUD = 921600
BAUD_CHOICES = (115200, 921600)
DEFAULT_CHANNEL = 1675
DEFAULT_NETWORK_ID = 0x12345678  # same default as CONFIG_DECTNRP_SAMPLE_NETWORK_ID
PCAP_SNAPLEN = 65535

# ---- UART frame format (must match src/sniffer_codec.h) -------------------
SYNC0 = 0xA5
SYNC1 = 0x5A
FT_DATA = 0x01
FT_CMD = 0x02
FT_RSP = 0x03
CMD_PING = 0x10
CMD_SET_CONFIG = 0x11
CMD_START = 0x12
CMD_STOP = 0x13


def crc16_ccitt(data, crc=0xFFFF):
    """CRC-16/CCITT-FALSE (init 0xFFFF, poly 0x1021, no reflection)."""
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = (
                ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
            )
    return crc


def encode_frame(ftype, payload=b""):
    body = struct.pack("<BH", ftype, len(payload)) + bytes(payload)
    return bytes([SYNC0, SYNC1]) + body + struct.pack("<H", crc16_ccitt(body))


class FrameDecoder:
    """Stream decoder with resynchronisation on sync pattern and CRC errors."""

    def __init__(self):
        self._buf = bytearray()
        self.crc_errors = 0

    def feed(self, data):
        self._buf += data
        frames = []
        sync = bytes([SYNC0, SYNC1])
        while True:
            start = self._buf.find(sync)
            if start < 0:
                # keep a trailing SYNC0 in case the sync pattern is split
                tail = self._buf[-1:]
                self._buf = bytearray(tail) if tail == bytes([SYNC0]) else bytearray()
                break
            if start > 0:
                del self._buf[:start]
            if len(self._buf) < 5:
                break
            length = self._buf[3] | (self._buf[4] << 8)
            total = 5 + length + 2
            if len(self._buf) < total:
                break
            body = bytes(self._buf[2 : 5 + length])
            crc_rx = self._buf[5 + length] | (self._buf[6 + length] << 8)
            if crc16_ccitt(body) == crc_rx:
                frames.append((body[0], body[3:]))
                del self._buf[:total]
            else:
                self.crc_errors += 1
                del self._buf[:1]  # drop the sync byte and search again
        return frames


class PcapWriter:
    """Minimal pcap writer (microsecond timestamps, little endian)."""

    def __init__(self, fp, linktype=DLT_DECT_NR_TAP):
        self._fp = fp
        self._fp.write(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, PCAP_SNAPLEN, linktype)
        )
        self._fp.flush()

    def write_packet(self, ts_ns, data):
        data = data[:PCAP_SNAPLEN]
        self._fp.write(
            struct.pack(
                "<IIII",
                ts_ns // 1_000_000_000,
                (ts_ns % 1_000_000_000) // 1000,
                len(data),
                len(data),
            )
        )
        self._fp.write(data)
        self._fp.flush()


class DeviceError(Exception):
    pass


class Device:
    """Command/response and data handling on top of a byte stream port."""

    def __init__(self, port, log):
        self.port = port
        self.log = log
        self.decoder = FrameDecoder()
        self.records = 0
        self._pending = []  # frames decoded but not yet consumed

    def send(self, ftype, payload=b""):
        self.port.write(encode_frame(ftype, payload))

    def read_frames(self):
        if self._pending:
            frames, self._pending = self._pending, []
            return frames
        data = self.port.read(4096)
        return self.decoder.feed(data) if data else []

    def transact(self, cmd, args=b"", timeout=3.0, on_data=None):
        """Send a command and wait for its response. DATA frames received in
        the meantime are passed to on_data (or dropped)."""
        self.send(FT_CMD, bytes([cmd]) + bytes(args))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            frames = self.read_frames()
            for idx, (ftype, payload) in enumerate(frames):
                if ftype == FT_RSP and len(payload) >= 2 and payload[0] == cmd:
                    # keep frames that arrived after the response in the same read
                    self._pending = frames[idx + 1 :] + self._pending
                    if payload[1] != 0:
                        status = struct.unpack("b", bytes([payload[1]]))[0]
                        raise DeviceError(
                            f"target status {status} for command 0x{cmd:02x}"
                        )
                    return
                if ftype == FT_DATA:
                    self.records += 1
                    if on_data:
                        on_data(payload)
        raise TimeoutError(f"no response to command 0x{cmd:02x} within {timeout:.1f}s")


def configure_and_start(dev, channel, network_id, on_data, log):
    for attempt in range(3):
        try:
            dev.transact(CMD_PING, timeout=1.5)
            break
        except TimeoutError:
            log(f"target not responding (attempt {attempt + 1}/3)")
            if attempt == 2:
                raise
    dev.transact(
        CMD_SET_CONFIG, struct.pack("<HI", channel, network_id), on_data=on_data
    )
    log(f"target configured: channel {channel}, network-id 0x{network_id:08x}")
    dev.transact(CMD_START, on_data=on_data)
    log("capture started")


def stop_target(dev, log, on_data=None):
    try:
        dev.transact(CMD_STOP, timeout=3.0, on_data=on_data)
        log("capture stopped, target idle")
    except (TimeoutError, DeviceError, OSError) as exc:
        log(f"could not confirm stop on target: {exc}")


class AsyncPcapWriter:
    """Writes pcap records from a background thread.

    The serial reader must never wait for the Wireshark FIFO: if it does, the
    UART receive buffer overflows and bytes are lost (seen as frame CRC errors).
    Records that do not fit into the queue are counted in ``dropped``.
    """

    def __init__(self, pcap, maxsize=50000):
        self._pcap = pcap
        self._queue = queue.Queue(maxsize=maxsize)
        self.dropped = 0
        self.error = None
        self._thread = threading.Thread(
            target=self._run, name="pcap-writer", daemon=True
        )
        self._thread.start()

    def write_packet(self, ts_ns, data):
        try:
            self._queue.put_nowait((ts_ns, bytes(data)))
        except queue.Full:
            self.dropped += 1

    def _run(self):
        while True:
            item = self._queue.get()
            if item is None:
                break
            if self.error is not None:
                continue  # pipe is gone, discard the rest
            try:
                self._pcap.write_packet(*item)
            except Exception as exc:  # noqa: BLE001 - e.g. BrokenPipeError
                self.error = exc

    def close(self, timeout=10.0):
        """Write out everything still queued, then stop the thread."""
        try:
            self._queue.put(None, timeout=timeout)
        except queue.Full:
            return
        self._thread.join(timeout)


TAP_TLV_TRANSACTION_ID = 7


def tap_transaction_id(record):
    """Transaction ID (TLV 7) of one DECT-NR-TAP record, or None."""
    if len(record) < 8:
        return None
    tlvs_len = struct.unpack_from("<H", record, 2)[0]
    for off in range(8, 8 + tlvs_len, 8):  # 8-byte header, then 8-byte TLVs
        if off + 8 > len(record):
            break
        typ, _ln, val = struct.unpack_from("<HHH", record, off)
        if typ == TAP_TLV_TRANSACTION_ID:
            return val
    return None


class SeqGapTracker:
    """Counts records missing from the transaction-ID sequence.

    Gaps show records that never reached the host (lost on the UART or
    dropped on the target). A burst is a run of consecutive missing records.
    """

    def __init__(self):
        self.last = None
        self.seen = 0
        self.missing = 0
        self.bursts = 0
        self.longest_burst = 0

    def add(self, record):
        seq = tap_transaction_id(record)
        if seq is None:
            return
        self.seen += 1
        if self.last is not None:
            gap = (seq - self.last - 1) & 0xFFFF
            if 0 < gap < 0x8000:  # forward gap; ignore reordering
                self.missing += gap
                self.bursts += 1
                self.longest_burst = max(self.longest_burst, gap)
        self.last = seq

    def summary(self):
        return (
            f"{self.missing} records missing by sequence "
            f"({self.bursts} gaps, longest {self.longest_burst})"
        )


def run_capture(port, fifo, baud, channel, network_id, log, stop_event, open_port=None):
    """Capture loop. open_port and fifo (a binary file object) are injectable."""
    port_obj = (open_port or _open_serial)(port, baud)
    dev = Device(port_obj, log)
    writer = None
    gaps = SeqGapTracker()

    def on_data(payload):
        gaps.add(payload)
        if writer is not None:
            writer.write_packet(time.time_ns(), payload)

    try:
        writer = AsyncPcapWriter(PcapWriter(fifo))
        configure_and_start(dev, channel, network_id, on_data, log)
        while not stop_event.is_set():
            if writer.error is not None:
                log(f"Wireshark closed the capture pipe ({writer.error})")
                break
            for ftype, payload in dev.read_frames():
                if ftype == FT_DATA:
                    dev.records += 1
                    on_data(payload)
                elif ftype == FT_RSP:
                    log(f"unexpected response {payload[:2].hex()}")
    finally:
        stop_target(dev, log, on_data=on_data)
        if writer is not None:
            writer.close()
        log(
            f"{dev.records} records received, {dev.decoder.crc_errors} frame CRC errors, "
            + gaps.summary()
            + (
                f", {writer.dropped} records dropped (FIFO too slow)"
                if writer and writer.dropped
                else ""
            )
        )
        for closeable in (port_obj, fifo):
            try:
                closeable.close()
            except Exception:  # noqa: BLE001 - best effort on shutdown
                pass


def _open_serial(port, baud):
    try:
        import serial  # pyserial
    except ImportError as exc:
        raise RuntimeError(
            "the pyserial package is not installed (see README)"
        ) from exc
    ser = serial.Serial(port, baudrate=baud, timeout=0.05)
    if hasattr(ser, "set_buffer_size"):  # pyserial, Windows only
        try:
            ser.set_buffer_size(rx_size=65536, tx_size=4096)
        except Exception:  # noqa: BLE001 - keep driver default
            pass
    return ser


def list_serial_ports():
    try:
        from serial.tools import list_ports
    except ImportError:
        return []
    return [p.device for p in list_ports.comports()]


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
    ports = list_serial_ports()
    if ports:
        print(
            "arg {number=0}{call=--serial-port}{display=Serial port}{type=selector}"
            "{tooltip=UART of the DECT NR+ sniffer target}{required=true}"
        )
        for i, p in enumerate(ports):
            print(
                f"value {{arg=0}}{{value={p}}}{{display={p}}}{{default={'true' if i == 0 else 'false'}}}"
            )
    else:
        print(
            "arg {number=0}{call=--serial-port}{display=Serial port}{type=string}"
            f"{{default={DEFAULT_PORT}}}{{tooltip=UART of the target, e.g. /dev/ttyACM0 or COM3}}"
            "{required=true}"
        )
    print(
        "arg {number=1}{call=--baudrate}{display=Baudrate}{type=selector}"
        "{tooltip=Must match the UART speed of the target firmware}"
    )
    for b in BAUD_CHOICES:
        print(
            f"value {{arg=1}}{{value={b}}}{{display={b} baud}}"
            f"{{default={'true' if b == DEFAULT_BAUD else 'false'}}}"
        )
    print(
        f"arg {{number=2}}{{call=--channel}}{{display=DECT NR+ channel}}{{type=unsigned}}"
        f"{{range=0,65535}}{{default={DEFAULT_CHANNEL}}}"
        "{tooltip=Carrier number to sniff, applied to the target when the capture starts}"
    )
    print(
        f"arg {{number=3}}{{call=--network-id}}{{display=Network ID}}{{type=unsigned}}"
        f"{{range=0,4294967295}}{{default={DEFAULT_NETWORK_ID}}}"
        "{tooltip=Decimal value. Default is the network ID of the Opener sample (0x32545279)}"
    )


def _parse_int(text, lo, hi, name):
    value = int(str(text), 0)
    if not lo <= value <= hi:
        raise ValueError(f"{name} out of range: {value}")
    return value


def parse_args(argv):
    p = argparse.ArgumentParser(description="DECT NR+ sniffer extcap for Wireshark")
    p.add_argument("--extcap-interfaces", action="store_true")
    p.add_argument("--extcap-interface", default=INTERFACE_ID)
    p.add_argument("--extcap-dlts", action="store_true")
    p.add_argument("--extcap-config", action="store_true")
    p.add_argument("--extcap-version", nargs="?", const="", default=None)
    p.add_argument("--extcap-capture-filter", default=None)
    p.add_argument("--capture", action="store_true")
    p.add_argument("--fifo", default=None)
    p.add_argument("--serial-port", default=DEFAULT_PORT)
    p.add_argument("--baudrate", default=str(DEFAULT_BAUD))
    p.add_argument("--channel", default=str(DEFAULT_CHANNEL))
    p.add_argument("--network-id", default=str(DEFAULT_NETWORK_ID))
    args, _unknown = p.parse_known_args(argv)
    return args


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    args = parse_args(argv)

    def log(msg):
        print(f"[dectnrp-sniffer] {msg}", file=sys.stderr, flush=True)

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
        channel = _parse_int(args.channel, 0, 65535, "channel")
        network_id = _parse_int(args.network_id, 0, 0xFFFFFFFF, "network-id")
        baud = _parse_int(args.baudrate, 1200, 4000000, "baudrate")
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

    try:
        with open(args.fifo, "wb", buffering=0) as fifo:
            run_capture(
                args.serial_port, fifo, baud, channel, network_id, log, stop_event
            )
    except Exception as exc:  # noqa: BLE001 - report to Wireshark log, exit non-zero
        log(f"capture failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
