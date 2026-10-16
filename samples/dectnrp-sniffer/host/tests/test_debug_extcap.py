"""Tests for the DEBUG extcap (dummy records, no hardware).

Run with the other host tests:
    python3 -m unittest discover -s host/tests -v
"""

import os
import random
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HOST_DIR = Path(__file__).resolve().parents[1]
DEBUG_EXTCAP = HOST_DIR / "dectnrp_sniffer_debug_extcap.py"
sys.path.insert(0, str(HOST_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import dectnrp_sniffer_debug_extcap as dbg  # noqa: E402
import test_host as th  # noqa: E402  (C codec helpers, reference walk, pcap reader)


def walk(rec):
    """Parse a record like the reference dissector does. Returns (tlvs, pcc_pdc)."""
    return th.reference_walk(rec)


class DebugRecordFormat(unittest.TestCase):
    def setUp(self):
        self.src = dbg.DummySource(base_channel=1677, span=4, seed=7, with_metrics=True)

    def test_records_pass_reference_walk(self):
        for i in range(40):
            rec = self.src.record(i)
            tlvs, rest = walk(rec)
            self.assertEqual(len(tlvs), 8)
            modem_len = struct.unpack_from("<H", rec, 4)[0]
            self.assertEqual(modem_len, len(rest))

    def test_channel_cycles_and_seq_increments(self):
        for i in range(20):
            tlvs, _ = walk(self.src.record(i))
            values = dict(tlvs[:4])
            self.assertEqual(values[th_const("TLV_CHANNEL")], 1677 + i % 4)
            self.assertEqual(values[th_const("TLV_TRANSACTION_ID")], i & 0xFFFF)

    def test_pdc_absent_every_seventh_record(self):
        for i in range(30):
            tlvs, rest = walk(self.src.record(i))
            data_type = dict(tlvs)[th_const("TLV_DATA_TYPE")]
            phy = (i // 5) % 2
            if i % dbg.PDC_ABSENT_EVERY == dbg.PDC_ABSENT_EVERY - 1:
                self.assertEqual(data_type, 3 if phy == 0 else 4)
                self.assertEqual(len(rest), 5 if phy == 0 else 10)
            else:
                self.assertEqual(data_type, 1 if phy == 0 else 2)
                self.assertGreater(len(rest), 5 if phy == 0 else 10)

    def test_without_metrics_is_padded_to_eight_entries(self):
        src = dbg.DummySource(seed=3, with_metrics=False)
        tlvs, _ = walk(src.record(0))
        self.assertEqual(len(tlvs), 8)
        self.assertEqual(sum(1 for typ, _ in tlvs if typ == 0), 4)

    def test_channel_wraps_at_65536(self):
        src = dbg.DummySource(base_channel=65535, span=2, seed=1)
        channels = [
            dict(walk(src.record(i))[0])[th_const("TLV_CHANNEL")] for i in range(4)
        ]
        self.assertEqual(channels, [65535, 0, 65535, 0])


def th_const(name):
    return getattr(dbg, name)


@unittest.skipUnless(th.HAVE_LIB, "codec library not available")
class PythonEncoderMatchesC(unittest.TestCase):
    def test_python_builder_equals_c_builder(self):
        rng = random.Random(42)
        for _ in range(60):
            phy = rng.randint(0, 1)
            pdc_len = rng.choice([0, rng.randint(1, 255)])
            pcc_len = 5 if phy == 0 else 10
            body = bytes(rng.getrandbits(8) for _ in range(pcc_len + pdc_len))
            channel = rng.randint(0, 65535)
            seq = rng.randint(0, 65535)
            if rng.random() < 0.5:
                metrics = tuple(rng.randint(-32768, 32767) for _ in range(4))
                py = dbg.build_tap_record(channel, seq, phy, body, pdc_len, metrics)
                c = th.c_build_record(
                    {
                        "phy_type": phy,
                        "pdc_len": pdc_len,
                        "channel": channel,
                        "seq": seq,
                        "metrics": metrics,
                    },
                    body,
                )
            else:
                py = dbg.build_tap_record(channel, seq, phy, body, pdc_len, None)
                c = th.c_build_record(
                    {
                        "phy_type": phy,
                        "pdc_len": pdc_len,
                        "channel": channel,
                        "seq": seq,
                    },
                    body,
                )
            self.assertEqual(py, c)


class CommandLine(unittest.TestCase):
    def run_extcap(self, *args, timeout=20):
        return subprocess.run(
            [sys.executable, str(DEBUG_EXTCAP), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def test_queries(self):
        out = self.run_extcap("--extcap-interfaces").stdout
        self.assertIn(f"value={dbg.INTERFACE_ID}", out)
        self.assertIn("number=304", self.run_extcap("--extcap-dlts").stdout)
        cfg = self.run_extcap(
            "--extcap-config", "--extcap-interface", dbg.INTERFACE_ID
        ).stdout
        for call in ("--interval-ms", "--channel", "--channel-span", "--metrics"):
            self.assertIn(f"call={call}", cfg)
        self.assertNotIn("serial", cfg.lower())

    def test_invalid_option_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            res = self.run_extcap(
                "--capture", "--fifo", os.path.join(d, "x.pcap"), "--interval-ms", "1"
            )
        self.assertEqual(res.returncode, 1)
        self.assertIn("interval-ms", res.stderr)

    def test_writes_count_records_then_exits(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "dummy.pcap")
            res = self.run_extcap(
                "--capture",
                "--fifo",
                path,
                "--count",
                "25",
                "--interval-ms",
                "10",
                "--channel",
                "1677",
                "--channel-span",
                "4",
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            pcap = th.read_pcap(path)
        self.assertEqual(pcap["linktype"], dbg.DLT_DECT_NR_TAP)
        self.assertEqual(len(pcap["packets"]), 25)
        for _sec, _usec, rec in pcap["packets"]:
            walk(rec)

    def test_sigterm_stops_endless_capture_cleanly(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "dummy.pcap")
            proc = subprocess.Popen(
                [
                    sys.executable,
                    str(DEBUG_EXTCAP),
                    "--capture",
                    "--fifo",
                    path,
                    "--count",
                    "0",
                    "--interval-ms",
                    "10",
                ],
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and not (
                    os.path.exists(path) and os.path.getsize(path) > 0
                ):
                    time.sleep(0.05)
                time.sleep(0.5)  # about 50 records at 10 ms interval
                proc.send_signal(signal.SIGTERM)
                _out, err = proc.communicate(timeout=10)
            finally:
                if proc.poll() is None:
                    proc.kill()
            self.assertEqual(proc.returncode, 0, err)
            self.assertIn("stopped after", err)
            pcap = th.read_pcap(path)
        self.assertGreaterEqual(len(pcap["packets"]), 5)
        for _sec, _usec, rec in pcap["packets"]:
            walk(rec)


if __name__ == "__main__":
    unittest.main()
