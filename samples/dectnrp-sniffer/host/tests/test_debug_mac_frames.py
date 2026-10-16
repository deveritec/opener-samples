"""Checks for the valid MAC frames of the DEBUG extcap (no hardware).

The expected bit positions are written by hand from ETSI TS 103 636-4 V2.2.1
(clauses 6.2.1, 6.3, 6.4) and compared with the generator output. The tests do
not reuse the generator's packing helpers.

Run from host/:  python3 -m unittest discover -s tests -p 'test_*.py' -v
"""

import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOST_DIR = Path(__file__).resolve().parents[1]
DEBUG_EXTCAP = HOST_DIR / "dectnrp_sniffer_debug_extcap.py"
sys.path.insert(0, str(HOST_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import dectnrp_sniffer_debug_extcap as dbg  # noqa: E402
import test_host as th  # noqa: E402

NW_SHORT = 0x4D  # LSB of Network ID 0x1A2B3C4D
FT_SHORT = 0x2C3D
PT_SHORT = 0x7A8B
FT_LONG = 0x0A1B2C3D
PT_LONG = 0x5E6F7A8B
FT_LONG_B = FT_LONG.to_bytes(4, "big")
PT_LONG_B = PT_LONG.to_bytes(4, "big")
CHANNEL = 1677


def bits(data, offset, width):
    """Read width bits at bit offset, MSB first, from a bytes object."""
    value = int.from_bytes(data, "big")
    shift = len(data) * 8 - offset - width
    return (value >> shift) & ((1 << width) - 1)


def split(rec):
    """Return (TAP data type, TAP channel, PCC+PDU bytes) of one record."""
    tlvs, rest = th.reference_walk(rec)
    values = dict(tlvs)
    return values[dbg.TLV_DATA_TYPE], values[dbg.TLV_CHANNEL], rest


class MacFrameLayout(unittest.TestCase):
    def setUp(self):
        self.src = dbg.DummySource(base_channel=CHANNEL, span=4, seed=1, payload="mac")

    def test_frame_cycle_and_tap_types(self):
        # Data type 1 = PCC Type 1 + PDC, 2 = PCC Type 2 + PDC. Beacon uses Type 1.
        for i in range(9):
            data_type, channel, rest = split(self.src.record(i))
            self.assertEqual(data_type, 1 if i % 3 == 0 else 2, f"record {i}")
            self.assertEqual(channel, CHANNEL + i % 4)
            self.assertGreater(len(rest), 5 if i % 3 == 0 else 10)

    def test_network_beacon_phy_control_field(self):
        _, _, rest = split(self.src.record(0))
        pcc = rest[:5]
        self.assertEqual(bits(pcc, 0, 3), 0b000)  # header format 000
        self.assertEqual(bits(pcc, 3, 1), 0)  # packet length in subslots
        self.assertEqual(bits(pcc, 8, 8), NW_SHORT)  # short network ID
        self.assertEqual(bits(pcc, 16, 16), FT_SHORT)  # transmitter: FT RD
        self.assertEqual(bits(pcc, 32, 4), 5)  # TX power code -8 dBm
        self.assertEqual(bits(pcc, 37, 3), 0)  # DF MCS BPSK

    def test_network_beacon_mac_pdu(self):
        _, channel, rest = split(self.src.record(0))
        pdu = rest[5:]
        self.assertEqual(len(pdu), 21)  # 1 + 7 + 2 + 11
        self.assertEqual(pdu[0], 0x01)  # MAC header type: beacon header
        self.assertEqual(pdu[1:4], bytes([0x1A, 0x2B, 0x3C]))  # 24 MSB of network ID
        self.assertEqual(pdu[4:8], FT_LONG_B)  # transmitter address
        self.assertEqual(
            pdu[8:10], bytes([0x48, 11])
        )  # MUX: ext 01, IE type 001000, len 11
        nb = pdu[10:]
        self.assertEqual(bits(nb, 0, 3), 0)  # reserved
        self.assertEqual(bits(nb, 3, 1), 1)  # TX power field included
        self.assertEqual(bits(nb, 4, 1), 0)  # power constraints: no
        self.assertEqual(bits(nb, 5, 1), 1)  # current cluster channel included
        self.assertEqual(bits(nb, 6, 2), 0)  # no additional NB channels
        self.assertEqual(bits(nb, 8, 4), 2)  # NB period 500 ms
        self.assertEqual(bits(nb, 12, 4), 2)  # CB period 100 ms
        self.assertEqual(bits(nb, 19, 13), channel)  # next cluster channel
        self.assertEqual(bits(nb, 32, 32), 100000)  # time to next, record 0
        self.assertEqual(bits(nb, 68, 4), 5)  # clusters max TX power -8 dBm
        self.assertEqual(bits(nb, 75, 13), channel)  # current cluster channel

    def test_association_request_phy_and_mac(self):
        _, _, rest = split(self.src.record(1))
        pcc = rest[:10]
        self.assertEqual(bits(pcc, 0, 3), 0b000)  # header format 000
        self.assertEqual(bits(pcc, 8, 8), NW_SHORT)
        self.assertEqual(bits(pcc, 16, 16), PT_SHORT)  # transmitter: PT RD
        self.assertEqual(bits(pcc, 40, 16), FT_SHORT)  # receiver: FT RD
        self.assertEqual(bits(pcc, 56, 2), 0)  # single spatial stream
        self.assertEqual(bits(pcc, 64, 4), 0)  # no feedback
        pdu = rest[10:]
        self.assertEqual(len(pdu), 27)  # 11 + 7 + 9
        self.assertEqual(pdu[0], 0x02)  # MAC header type: unicast header
        self.assertEqual(bits(pdu[1:3], 3, 1), 1)  # reset bit
        self.assertEqual(bits(pdu[1:3], 4, 12), 1)  # sequence number = record index
        self.assertEqual(pdu[3:7], FT_LONG_B)  # receiver address
        self.assertEqual(pdu[7:11], PT_LONG_B)  # transmitter address
        self.assertEqual(pdu[11:13], bytes([0x4A, 5]))  # MUX: IE type 001010, len 5
        ar = pdu[13:18]
        self.assertEqual(bits(ar, 0, 3), 0)  # setup cause: initial association
        self.assertEqual(bits(ar, 3, 3), 1)  # number of flows
        self.assertEqual(bits(ar, 6, 1), 0)  # power constraints
        self.assertEqual(bits(ar, 7, 1), 0)  # FT mode: no (PT only)
        self.assertEqual(ar[2:4], bytes([0x24, 0x24]))  # HARQ TX/RX 1 process, 1 ms
        self.assertEqual(ar[4], 0x03)  # reserved 0, flow ID user plane 1
        self.assertEqual(pdu[18:20], bytes([0x54, 7]))  # MUX: RD capability IE, len 7
        rdc = pdu[20:]
        self.assertEqual(rdc[0], 0x02)  # 0 extra PHY caps, release 2
        self.assertEqual(bits(rdc, 12, 2), 0)  # operating modes: PT only
        self.assertEqual(bits(rdc, 16, 3), 0)  # MAC security: none
        self.assertEqual(bits(rdc, 19, 3), 4)  # DLC service types 0-3
        self.assertEqual(bits(rdc, 25, 3), 2)  # power class III

    def test_association_response_phy_and_mac(self):
        _, _, rest = split(self.src.record(2))
        pcc = rest[:10]
        self.assertEqual(bits(pcc, 0, 3), 0b001)  # header format 001
        self.assertEqual(bits(pcc, 16, 16), FT_SHORT)  # transmitter: FT RD
        self.assertEqual(bits(pcc, 40, 16), PT_SHORT)  # receiver: PT RD
        self.assertEqual(bits(pcc, 58, 6), 0)  # reserved in format 001
        pdu = rest[10:]
        self.assertEqual(len(pdu), 23)  # 11 + 3 + 9
        self.assertEqual(pdu[0], 0x02)
        self.assertEqual(bits(pdu[1:3], 3, 1), 1)
        self.assertEqual(pdu[3:7], PT_LONG_B)  # receiver address
        self.assertEqual(pdu[7:11], FT_LONG_B)  # transmitter address
        self.assertEqual(
            pdu[11:14], bytes([0x4B, 1, 0x9C])
        )  # MUX: IE 001011, len 1, ACK + all flows
        self.assertEqual(bits(pdu[13:14], 0, 1), 1)  # ACK/NACK = accepted
        self.assertEqual(bits(pdu[13:14], 3, 3), 0b111)  # all flows accepted
        self.assertEqual(pdu[14:16], bytes([0x54, 7]))  # MUX: RD capability IE
        rdc = pdu[16:]
        self.assertEqual(bits(rdc, 12, 2), 2)  # operating modes: PT and FT

    def test_mux_lengths_cover_each_pdu_exactly(self):
        common_len = {0x01: 7, 0x02: 10}
        expected_ies = {0: [0x08], 1: [0x0A, 0x14], 2: [0x0B, 0x14]}
        for i in range(9):
            _, _, rest = split(self.src.record(i))
            pdu = rest[5:] if i % 3 == 0 else rest[10:]
            pos = 1 + common_len[pdu[0]]
            ies = []
            while pos < len(pdu):
                self.assertEqual(
                    pdu[pos] >> 6, 1, f"record {i}: MAC extension must be 01"
                )
                ies.append(pdu[pos] & 0x3F)
                pos += 2 + pdu[pos + 1]
            self.assertEqual(pos, len(pdu), f"record {i}: MUX lengths do not match PDU")
            self.assertEqual(ies, expected_ies[i % 3], f"record {i}")

    def test_identifiers_are_not_reserved(self):
        self.assertNotEqual(dbg.NETWORK_ID & 0xFF, 0)
        self.assertNotEqual(dbg.NETWORK_ID >> 8, 0)
        for long_id in (dbg.FT_LONG_RD_ID, dbg.PT_LONG_RD_ID):
            self.assertNotIn(long_id, (0x00000000, 0xFFFFFFFE, 0xFFFFFFFF))
        for short_id in (dbg.FT_SHORT_RD_ID, dbg.PT_SHORT_RD_ID):
            self.assertNotIn(short_id, (0x0000, 0xFFFF))

    def test_mac_mode_is_deterministic_and_has_no_crc_errors(self):
        other = dbg.DummySource(base_channel=CHANNEL, span=4, seed=99, payload="mac")
        for i in range(30):
            rec = self.src.record(i)
            self.assertEqual(rec, other.record(i))  # no RNG in MAC mode
            data_type, _, _ = split(rec)
            self.assertIn(data_type, (1, 2))  # PDC always present

    def test_pcc_frames_are_dissectable_by_tap_walk(self):
        for i in range(30):
            rec = self.src.record(i)
            tlvs, rest = th.reference_walk(rec)
            self.assertEqual(len(tlvs), dbg.TAP_MIN_TLVS)
            modem_len = struct.unpack_from("<H", rec, 4)[0]
            self.assertEqual(modem_len, len(rest))


class MacFrameCommandLine(unittest.TestCase):
    def run_extcap(self, *args, timeout=20):
        return subprocess.run(
            [sys.executable, str(DEBUG_EXTCAP), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def test_config_offers_frame_selector(self):
        cfg = self.run_extcap(
            "--extcap-config", "--extcap-interface", dbg.INTERFACE_ID
        ).stdout
        self.assertIn("call=--frames", cfg)
        self.assertIn("value {arg=4}{value=mac}", cfg)
        self.assertIn("value {arg=4}{value=random}", cfg)

    def test_invalid_frame_mode_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            res = self.run_extcap(
                "--capture", "--fifo", os.path.join(d, "x.pcap"), "--frames", "bogus"
            )
        self.assertEqual(res.returncode, 1)
        self.assertIn("frames", res.stderr)

    def test_default_capture_writes_valid_mac_frames(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "mac.pcap")
            res = self.run_extcap(
                "--capture", "--fifo", path, "--count", "9", "--interval-ms", "10"
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            pcap = th.read_pcap(path)
        self.assertEqual(pcap["linktype"], dbg.DLT_DECT_NR_TAP)
        self.assertEqual(len(pcap["packets"]), 9)
        types = [split(rec)[0] for _s, _u, rec in pcap["packets"]]
        self.assertEqual(types, [1, 2, 2, 1, 2, 2, 1, 2, 2])


if __name__ == "__main__":
    unittest.main()
