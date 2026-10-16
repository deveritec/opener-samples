"""
Tests for the DECT NR+ sniffer extcap.

Run from the repository root:
    python3 -m unittest discover -s host/tests -v

The record and frame encoding is cross-checked against the C codec
(src/sniffer_codec.c). The library is built automatically with the system C
compiler, or taken from the environment variable SNIFFER_CODEC_LIB.
The "target" is emulated on a pseudo terminal, so no hardware is needed.
"""

import ctypes
import os
import select
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tty
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOST_DIR = HERE.parent
REPO = HOST_DIR.parent
sys.path.insert(0, str(HOST_DIR))

import dectnrp_sniffer_extcap as ex  # noqa: E402


def build_codec_library():
    env = os.environ.get("SNIFFER_CODEC_LIB")
    if env:
        return env
    out_dir = tempfile.mkdtemp(prefix="sniffer-codec-")
    out = os.path.join(out_dir, "libsniffer_codec.so")
    cc = os.environ.get("CC", "cc")
    subprocess.run(
        [
            cc,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-shared",
            "-fPIC",
            "-O1",
            f"-I{REPO / 'src'}",
            str(REPO / "src" / "sniffer_codec.c"),
            "-o",
            out,
        ],
        check=True,
    )
    return out


try:
    LIB = ctypes.CDLL(build_codec_library())
    HAVE_LIB = True
except (OSError, subprocess.CalledProcessError):  # pragma: no cover
    LIB = None
    HAVE_LIB = False


class Metrics(ctypes.Structure):
    _fields_ = [
        ("pcc_rssi2", ctypes.c_int16),
        ("pcc_snr", ctypes.c_int16),
        ("pdc_rssi2", ctypes.c_int16),
        ("pdc_snr", ctypes.c_int16),
    ]


class RxInfo(ctypes.Structure):
    _fields_ = [
        ("phy_type", ctypes.c_uint8),
        ("pdc_len", ctypes.c_uint16),
        ("channel", ctypes.c_uint16),
        ("seq", ctypes.c_uint16),
        ("has_metrics", ctypes.c_bool),
        ("metrics", Metrics),
    ]


class Decoder(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_uint8),
        ("type", ctypes.c_uint8),
        ("len", ctypes.c_uint16),
        ("pos", ctypes.c_uint16),
        ("crc_rx", ctypes.c_uint16),
        ("crc", ctypes.c_uint16),
        ("crc_errors", ctypes.c_uint32),
        ("payload", ctypes.c_uint8 * 64),
    ]


if HAVE_LIB:
    LIB.sniff_build_tap_record.restype = ctypes.c_size_t
    LIB.sniff_build_tap_record.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(RxInfo),
        ctypes.c_void_p,
    ]
    LIB.sniff_frame_encode.restype = ctypes.c_size_t
    LIB.sniff_frame_encode.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint8,
        ctypes.c_void_p,
        ctypes.c_uint16,
    ]
    LIB.sniff_crc16.restype = ctypes.c_uint16
    LIB.sniff_crc16.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    LIB.sniff_decoder_init.argtypes = [ctypes.POINTER(Decoder)]
    LIB.sniff_decoder_feed.restype = ctypes.c_bool
    LIB.sniff_decoder_feed.argtypes = [ctypes.POINTER(Decoder), ctypes.c_uint8]


def c_build_record(info_kwargs, body):
    info = RxInfo()
    info.phy_type = info_kwargs.get("phy_type", 0)
    info.pdc_len = info_kwargs.get("pdc_len", 0)
    info.channel = info_kwargs.get("channel", 0)
    info.seq = info_kwargs.get("seq", 0)
    if "metrics" in info_kwargs:
        info.has_metrics = True
        info.metrics = Metrics(*info_kwargs["metrics"])
    buf = (ctypes.c_uint8 * 1024)()
    body_buf = (ctypes.c_uint8 * max(1, len(body)))(*body)
    n = LIB.sniff_build_tap_record(buf, 1024, ctypes.byref(info), body_buf)
    assert n > 0
    return bytes(buf[:n])


def c_encode_frame(ftype, payload):
    out = (ctypes.c_uint8 * 600)()
    pl = (ctypes.c_uint8 * max(1, len(payload)))(*payload)
    n = LIB.sniff_frame_encode(out, 600, ftype, pl, len(payload))
    return bytes(out[:n])


def reference_walk(rec):
    """Python version of the Wireshark dissector TLV walk (packet-dect-nr-tap.c)."""
    assert len(rec) >= 8 + 8 * 8, "below reference MIN_LENGTH"
    tlvs_len = struct.unpack_from("<H", rec, 2)[0]
    tlvs = []
    off = 8
    while off < 8 + tlvs_len:
        typ, vlen = struct.unpack_from("<HH", rec, off)
        assert vlen <= 4, "invalid TLV length"
        value = None
        if vlen == 2:
            fmt = "<h" if typ in (3, 4, 5, 6) else "<H"
            value = struct.unpack_from(fmt, rec, off + 4)[0]
        tlvs.append((typ, value))
        off += 8
    return tlvs, rec[8 + tlvs_len :]


class PtyPort:
    """Byte stream port with the same read/write/close API as pyserial."""

    def __init__(self, fd):
        self.fd = fd

    def read(self, n):
        r, _, _ = select.select([self.fd], [], [], 0.05)
        return os.read(self.fd, n) if r else b""

    def write(self, data):
        view = memoryview(bytes(data))
        while view:
            written = os.write(self.fd, view)
            view = view[written:]

    def close(self):
        os.close(self.fd)


class FakeTarget(threading.Thread):
    """Emulates the Zephyr sniffer firmware on the master side of a pty."""

    def __init__(self, master_fd, records=20, corrupt_frame=False):
        super().__init__(daemon=True)
        self.fd = master_fd
        self.records = records
        self.corrupt_frame = corrupt_frame
        self.dec = ex.FrameDecoder()
        self.commands = []
        self.running = False
        self.sent = 0
        self.stopped = threading.Event()
        self.quit = threading.Event()

    def run(self):
        while not self.quit.is_set():
            r, _, _ = select.select([self.fd], [], [], 0.005)
            if r:
                try:
                    chunk = os.read(self.fd, 4096)
                except OSError:  # host closed its end of the pty
                    break
                for ftype, payload in self.dec.feed(chunk):
                    if ftype != ex.FT_CMD:
                        continue
                    cmd, args = payload[0], payload[1:]
                    self.commands.append((cmd, args))
                    if cmd == ex.CMD_START:
                        self.running = True
                    if cmd == ex.CMD_STOP:
                        self.running = False
                        self.stopped.set()
                    os.write(self.fd, ex.encode_frame(ex.FT_RSP, bytes([cmd, 0])))
            elif self.running and self.sent < self.records:
                seq = self.sent
                pdc_len = seq % 7
                body = bytes(range(0x10, 0x10 + 5 + pdc_len))  # 5-byte PCC + PDC
                rec = c_build_record(
                    {"phy_type": 0, "pdc_len": pdc_len, "channel": 1677, "seq": seq},
                    body,
                )
                if self.corrupt_frame and seq == 3:
                    bad = bytearray(ex.encode_frame(ex.FT_DATA, rec))
                    bad[6] ^= 0x40
                    os.write(self.fd, bytes(bad))
                os.write(self.fd, ex.encode_frame(ex.FT_DATA, rec))
                self.sent += 1
                time.sleep(0.002)

    def stop(self):
        self.quit.set()
        self.join(timeout=2)


def make_pty():
    master, slave = os.openpty()
    tty.setraw(slave)
    return master, slave


def read_pcap(path):
    data = Path(path).read_bytes()
    magic, vmaj, vmin, _tz, _sig, snaplen, linktype = struct.unpack_from(
        "<IHHiIII", data, 0
    )
    off = 24
    packets = []
    while off < len(data):
        sec, usec, incl, _orig = struct.unpack_from("<IIII", data, off)
        off += 16
        packets.append((sec, usec, data[off : off + incl]))
        off += incl
    return {
        "magic": magic,
        "version": (vmaj, vmin),
        "linktype": linktype,
        "packets": packets,
    }


@unittest.skipUnless(HAVE_LIB, "codec library not available")
class CodecCrossCheck(unittest.TestCase):
    def test_crc_matches_c(self):
        for data in (b"123456789", b"", bytes(range(256))):
            self.assertEqual(ex.crc16_ccitt(data), LIB.sniff_crc16(data, len(data)))
        self.assertEqual(ex.crc16_ccitt(b"123456789"), 0x29B1)

    def test_python_frame_decoded_by_c_decoder(self):
        payload = bytes([ex.CMD_SET_CONFIG]) + struct.pack(
            "<HI", 1677, ex.DEFAULT_NETWORK_ID
        )
        frame = ex.encode_frame(ex.FT_CMD, payload)
        dec = Decoder()
        LIB.sniff_decoder_init(ctypes.byref(dec))
        got = None
        for b in frame:
            if LIB.sniff_decoder_feed(ctypes.byref(dec), b):
                got = bytes(dec.payload[: dec.len])
                self.assertEqual(dec.type, ex.FT_CMD)
        self.assertEqual(got, payload)

    def test_c_frame_decoded_by_python(self):
        payload = b"\x12\x00\x01\x02"
        frame = c_encode_frame(ex.FT_CMD, payload)
        self.assertEqual(frame, ex.encode_frame(ex.FT_CMD, payload))
        self.assertEqual(ex.FrameDecoder().feed(frame), [(ex.FT_CMD, payload)])

    def test_record_structure_is_dissectable_like_reference(self):
        body = bytes(range(0x30, 0x30 + 10 + 20))
        rec = c_build_record(
            {
                "phy_type": 1,
                "pdc_len": 20,
                "channel": 1677,
                "seq": 0x1234,
                "metrics": (-87, 40, -84, -8),
            },
            body,
        )
        tlvs, rest = reference_walk(rec)
        values = dict(tlvs)
        self.assertEqual([t for t, _ in tlvs], [1, 2, 7, 8, 3, 4, 5, 6])
        self.assertEqual(values[1], 2)  # 80-bit PCC, PDC included
        self.assertEqual(values[2], 0)  # header status valid
        self.assertEqual(values[7], 0x1234)  # transaction id
        self.assertEqual(values[8], 1677)  # channel
        self.assertEqual(values[3], -87)  # PCC RSSI2
        self.assertEqual(rest, body)

    def test_short_record_is_padded_to_reference_minimum(self):
        rec = c_build_record(
            {"phy_type": 0, "pdc_len": 0, "channel": 5, "seq": 9}, bytes(5)
        )
        tlvs, rest = reference_walk(rec)
        self.assertEqual(len(tlvs), 8)
        self.assertEqual([t for t, _ in tlvs][4:], [0, 0, 0, 0])
        self.assertEqual(len(rest), 5)


@unittest.skipUnless(HAVE_LIB, "codec library not available")
class CaptureEndToEnd(unittest.TestCase):
    def test_capture_configures_streams_and_stops_cleanly(self):
        master, slave = make_pty()
        target = FakeTarget(master, records=25, corrupt_frame=True)
        target.start()
        fifo_path = os.path.join(tempfile.mkdtemp(), "capture.pcap")
        stop = threading.Event()
        logs = []

        def run():
            with open(fifo_path, "wb", buffering=0) as fifo:
                ex.run_capture(
                    "fake",
                    fifo,
                    921600,
                    1677,
                    ex.DEFAULT_NETWORK_ID,
                    logs.append,
                    stop,
                    open_port=lambda p, b: PtyPort(slave),
                )

        th = threading.Thread(target=run)
        th.start()
        deadline = time.time() + 10
        while target.sent < 25 and time.time() < deadline:
            time.sleep(0.01)
        time.sleep(0.3)
        stop.set()
        th.join(timeout=10)
        self.assertFalse(th.is_alive(), "capture did not terminate")
        target.stop()

        cmds = [c for c, _ in target.commands]
        self.assertEqual(
            cmds[:4], [ex.CMD_PING, ex.CMD_SET_CONFIG, ex.CMD_START, ex.CMD_STOP]
        )
        cfg = dict(target.commands)[ex.CMD_SET_CONFIG]
        self.assertEqual(struct.unpack("<HI", cfg), (1677, ex.DEFAULT_NETWORK_ID))
        self.assertTrue(target.stopped.is_set())

        pcap = read_pcap(fifo_path)
        self.assertEqual(pcap["magic"], 0xA1B2C3D4)
        self.assertEqual(pcap["linktype"], 304)
        self.assertEqual(len(pcap["packets"]), 25)
        for i, (_s, _u, data) in enumerate(pcap["packets"]):
            tlvs, rest = reference_walk(data)
            self.assertEqual(dict(tlvs)[7], i)
            self.assertEqual(dict(tlvs)[8], 1677)
            self.assertEqual(rest, bytes(range(0x10, 0x10 + 5 + (i % 7))))  # PCC || PDC
        self.assertTrue(
            any("1 frame CRC errors" in m or "CRC errors" in m for m in logs)
        )

    def test_sigterm_stops_cli_and_closes_target_cleanly(self):
        master, slave = make_pty()
        target = FakeTarget(master, records=10**6)
        target.start()
        tmp = tempfile.mkdtemp()
        out_path = os.path.join(tmp, "capture.pcap")
        harness = Path(tmp) / "harness.py"
        harness.write_text(
            "import os, sys\n"
            f"sys.path.insert(0, {str(HOST_DIR)!r})\n"
            f"sys.path.insert(0, {str(HOST_DIR / 'tests')!r})\n"
            "import dectnrp_sniffer_extcap as ex\n"
            "from test_host import PtyPort\n"
            "fd = int(os.environ['PTY_FD'])\n"
            "ex._open_serial = lambda port, baud: PtyPort(fd)\n"
            "sys.exit(ex.main(sys.argv[1:]))\n"
        )
        env = dict(os.environ, PTY_FD=str(slave))
        proc = subprocess.Popen(
            [
                sys.executable,
                str(harness),
                "--extcap-interface",
                "dectnrp-sniffer",
                "--capture",
                "--fifo",
                out_path,
                "--serial-port",
                "/dev/null",
                "--baudrate",
                "921600",
                "--channel",
                "1677",
                "--network-id",
                str(ex.DEFAULT_NETWORK_ID),
            ],
            env=env,
            pass_fds=(slave,),
            stderr=subprocess.PIPE,
        )
        deadline = time.time() + 15
        while (
            not target.running
            or not os.path.exists(out_path)
            or os.path.getsize(out_path) < 24 + 16 * 5
        ) and time.time() < deadline:
            time.sleep(0.02)
        proc.send_signal(signal.SIGTERM)
        try:
            _out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            target.stop()
            self.fail("CLI did not exit after SIGTERM")
        target.stop()
        os.close(slave)
        self.assertEqual(proc.returncode, 0, err.decode(errors="replace"))
        self.assertTrue(target.stopped.is_set(), "target never received STOP")
        pcap = read_pcap(out_path)
        self.assertEqual(pcap["linktype"], 304)
        self.assertGreater(len(pcap["packets"]), 0)
        self.assertIn(b"capture stopped", err)

    def test_invalid_options_are_rejected(self):
        self.assertEqual(
            ex.main(["--capture", "--fifo", "/tmp/x", "--channel", "70000"]), 1
        )
        self.assertEqual(
            ex.main(["--capture", "--fifo", "/tmp/x", "--network-id", "0x1FFFFFFFF"]), 1
        )
        self.assertEqual(ex.main(["--capture"]), 1)


class ExtcapQueries(unittest.TestCase):
    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, str(HOST_DIR / "dectnrp_sniffer_extcap.py"), *args],
            capture_output=True,
            text=True,
            timeout=20,
        )
        return proc.returncode, proc.stdout

    def test_interfaces_dlts_and_config(self):
        rc, out = self._run("--extcap-interfaces")
        self.assertEqual(rc, 0)
        self.assertIn("interface {value=dectnrp-sniffer}", out)
        rc, out = self._run("--extcap-dlts", "--extcap-interface", "dectnrp-sniffer")
        self.assertIn("dlt {number=304}", out)
        rc, out = self._run("--extcap-config", "--extcap-interface", "dectnrp-sniffer")
        self.assertIn("{call=--channel}", out)
        self.assertIn("{call=--network-id}", out)
        self.assertIn(f"{{default={ex.DEFAULT_CHANNEL}}}", out)
        self.assertIn(f"{{default={ex.DEFAULT_NETWORK_ID}}}", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
