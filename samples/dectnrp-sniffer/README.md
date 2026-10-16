# Opener DECT NR+ sniffer

Copyright (c) 2026 Deveritec GmbH.
SPDX-License-Identifier: Apache-2.0

## Overview

This sample turns an nRF9151 DK into a DECT NR+ sniffer for Wireshark.
It sits next to the `dectnrp-driver` sample and uses the same driver API.

```text
nRF9151 (Zephyr, this sample)              Host PC
------------------------------             -----------------------------------------
dectnrp driver, RX windows      --UART-->  dectnrp_sniffer_extcap.py (Wireshark extcap)
DECT-NR-TAP record per packet     921600   - configures channel / network ID
                                           - writes pcap, linktype 304, into FIFO
commands (PING, SET_CONFIG,     <--UART--  - STOP and clean exit on SIGTERM/SIGINT
          START, STOP)                     Wireshark: DECT NR TAP dissector (304)
```

Each received packet is sent as one DECT-NR-TAP record (`LINKTYPE_DECT_NR_TAP`,
DLT 304, see [DSRCorporation/dect-nr-tap](https://github.com/DSRCorporation/dect-nr-tap)):
an 8-byte header, metadata entries (data type, header status, transaction ID,
channel and, once implemented, PCC/PDC RSSI and SNR), then the PCC bytes
followed by the PDC bytes.

A second extcap, the **debug generator**, produces the same record format
without any hardware. Use it to check the Wireshark setup (see
[Debug generator (no hardware)](#debug-generator-no-hardware)).

## Repository layout

```text
samples/dectnrp-sniffer/
├── CMakeLists.txt, Kconfig, prj.conf, sample.yaml
├── boards/nrf9151dk_nrf9151_ns.overlay   UART0 at 921600 baud
├── src/main.c                            Zephyr firmware (RX loop, commands, UART)
├── src/sniffer_codec.[ch]                UART framing and DECT-NR-TAP record (plain C)
├── tests/test_codec.c                    C unit test for the codec
├── README.md
└── host/
    ├── dectnrp_sniffer_extcap.py         Wireshark extcap: real sniffer (serial)
    ├── dectnrp_sniffer_extcap.bat        Windows wrapper for the real sniffer
    ├── dectnrp_sniffer_debug_extcap.py   Wireshark extcap: debug generator (no hardware)
    ├── dectnrp_sniffer_debug_extcap.bat  Windows wrapper for the debug generator
    └── tests/
        ├── test_host.py                  end-to-end tests with an emulated target
        ├── test_debug_extcap.py          tests for the debug generator (dummy records)
        └── test_debug_mac_frames.py      tests for the valid MAC frames of the debug generator
```

## Requirements

- **Target:** nRF9151 DK and the same NCS/Zephyr workspace as the
  `dectnrp-driver` sample.
- **Host:** Wireshark 4.7.4 or newer with the DECT NR TAP dissector. The
  dissector is present in a Wireshark 4.7.4 development build. Check it with
  `tshark -G protocols | grep -i dect`.
- **Python 3.8+.** The real sniffer needs the `pyserial` package. The debug
  generator does not need it.

## Build and flash the target

Use the same workspace as `dectnrp-driver`:

```bash
west build -p always -b nrf9151dk/nrf9151/ns samples/dectnrp-sniffer
west flash
```

The sniffer stream uses UART0 at 921600 baud. The console is disabled, so
logs go to RTT only.

## Install the extcaps on the host

Requirements for the real sniffer: `pyserial` (Linux/macOS:
`python3 -m pip install pyserial`, Windows: `py -m pip install pyserial`).

Copy **all** `.py` files from `host/` into the Wireshark extcap directory.
The debug generator imports `dectnrp_sniffer_extcap.py`, so both files must
be in the same directory.

- **Linux:** `~/.local/lib/wireshark/extcap/` (make the .py files executable:
  `chmod +x`). The serial port needs permission, e.g.
  `sudo usermod -a -G dialout $USER`, followed by a new login. (to set a link use `./install_extcap_link.sh -f`)
- **Windows:** `%APPDATA%\Wireshark\extcap\`. Copy the `.py` and `.bat` files.
- **macOS:** `~/.config/wireshark/extcap/` (make the .py files executable).

Restart Wireshark. Two interfaces then appear in the capture interface list:

- *DECT NR+ Sniffer (Opener)*: the real sniffer
- *DECT NR+ Sniffer - DEBUG generator (no hardware)*: the debug generator

## Use the real sniffer

1. Select *DECT NR+ Sniffer (Opener)* and open its options (gear icon).
2. Set *Serial port* (e.g. `/dev/ttyACM0` or `COM3`), *Baudrate* (921600),
   *DECT NR+ channel* (default 1677) and *Network ID* (default 844386937, which
   is 0x32545279).
3. Press *Start*. The extcap configures the target, starts RX and streams packets live.
4. Press *Stop*. The extcap sends STOP to the target, waits for the
   acknowledgement and exits.

Channel and network ID are applied when the capture starts. To change them,
stop the capture and start it again.

Without Wireshark (for debugging):

```bash
python3 host/dectnrp_sniffer_extcap.py --extcap-interface dectnrp-sniffer \
    --capture --fifo /tmp/dect.pcap --serial-port /dev/ttyACM0 \
    --baudrate 921600 --channel 1677 --network-id 844386937
```

Ctrl+C stops the capture cleanly. Log lines go to stderr.

## Debug generator (no hardware)

The debug generator writes a continuous stream of dummy DECT-NR-TAP records
into the capture file or FIFO. It needs no serial port and no target. Use it to
check that Wireshark shows the interface, the DLT, the dissector and the
TLV fields correctly.

In Wireshark the options are:

- *Interval*: time between two records, 10 to 10000 ms (default 200)
- *DECT NR+ channel*: first channel of the cycle (default 1677)
- *Channels in cycle*: 1 to 16 (default 4)
- *RSSI / SNR*: include the PCC/PDC metrics (default on)
- *Frame content*: `Valid MAC frames` (default) or `Random payload`

### Valid MAC frames (default)

The records cycle through three frames:

| # | Message | PHY control field | MAC PDU |
| --- | --- | --- | --- |
| 1 | Network Beacon (FT RD) | Type 1 (40 bit) | Beacon Header, MUX (IE 8), Network Beacon IE, 11 bytes |
| 2 | Association Request (PT RD to FT RD) | Type 2, header format 000 | Unicast Header, MUX (IE 10), Association Request IE, MUX (IE 20), RD Capability IE |
| 3 | Association Response (FT RD to PT RD) | Type 2, header format 001 | Unicast Header, MUX (IE 11), Association Response IE (accepted), MUX (IE 20), RD Capability IE |

Fixed demo identifiers: Network ID `0x1A2B3C4D` (short NW ID `0x4D`), FT RD
Long/Short ID `0x0A1B2C3D` / `0x2C3D`, PT RD Long/Short ID `0x5E6F7A8B` /
`0x7A8B`. The frames are deterministic (same record index gives the same bytes).
The sequence number, NDI and time to next cluster beacon change from record to
record. The reset bit is set on the association frames. The channel fields carry the channel of the record (13 bits).

Spec sources: ETSI TS 103 636-4 V2.2.1, clauses 6.2.1 (Tables 6.2.1-1, 6.2.1-2,
6.2.1-2a), 6.3.2 to 6.3.4, 6.4.2.2, 6.4.2.4, 6.4.2.5 and 6.4.3.5. The bit
offsets were cross-checked by hand against the field masks in the Wireshark
dissector `packet-dect-nr.c`.

Verification status:

- Verified in this repository: the frame layouts match the spec tables and the
  dissector field masks, and `test_debug_mac_frames.py` checks every field
  position separately from the generator code.
- Not verified yet: a live decode in Wireshark 4.7.4. Open a capture from the
  debug generator in Wireshark and check the Network Beacon, Association
  Request and Association Response trees before you rely on them.
- Not generated yet: Cluster Beacon, Association Release, Reconfiguration,
  RD Broadcasting and Unicast data frames, MAC security, and the PHY
  packet length (fixed code 3 = 4 subslots, not derived from the PDU size).
- The Unicast Header DWA bit is set to 0. The spec text extracted for clause
  6.3.3.3 does not describe it, so the value is taken from the dissector.

### Random payload

The payload mode *Random payload* writes random PCC/PDC bytes with a changing
PHY type, a PDC CRC error on every 7th record (data type 3 or 4) and smoothly
changing RSSI and SNR. Only the TAP header is meaningful, so the DECT NR MAC
payload does not decode to anything useful. Use this mode to test the TAP
format and the TLV handling.

### Command line

```bash
python3 host/dectnrp_sniffer_debug_extcap.py --capture --fifo /tmp/dummy.pcap \
    --interval-ms 200 --channel 1677 --channel-span 4 --metrics on \
    --frames mac --count 100
```

Additional options (not shown in Wireshark): `--frames {mac,random}` (default
`mac`; the Wireshark selector is *Frame content*), `--seed` (default 1; affects
only the random payload) and `--count` (0 = run until stopped). SIGTERM or
Ctrl+C stops the generator cleanly and the file stays complete.

## UART protocol

Frame (both directions, little endian):

```text
0xA5 0x5A | TYPE (1) | LEN (2) | PAYLOAD (LEN) | CRC16 (2)
```

CRC-16/CCITT-FALSE (init 0xFFFF, poly 0x1021) over TYPE, LEN and PAYLOAD.
The decoder resynchronises on the sync bytes after CRC errors.

| TYPE | Name | Direction      | Payload                          |
| ---- | ---- | -------------- | -------------------------------- |
| 0x01 | DATA | target → host  | one DECT-NR-TAP record           |
| 0x02 | CMD  | host → target  | `[cmd id][arguments]`            |
| 0x03 | RSP  | target → host  | `[cmd id][status int8, 0 = OK]`  |

| Command        | Arguments                 | Behaviour                                                                                         |
| -------------- | ------------------------- | ------------------------------------------------------------------------------------------------- |
| 0x10 PING      | -                         | RSP                                                                                               |
| 0x11 SET_CONFIG| u16 channel, u32 network ID (LE) | Network ID goes to the dectnrp driver at once. Channel applies to the next RX window. RSP after apply. |
| 0x12 START     | -                         | Start continuous RX. RSP.                                                                         |
| 0x13 STOP      | -                         | Stop after the current RX window. RSP.                                                            |

## DECT-NR-TAP record produced by the sniffer

Is based on the wireshark dissector [packet-dect-nr-tap.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-dect-nr-tap.c)

Header (8 bytes, little endian):

- byte 0: version (1)
- byte 1: reserved (0)
- bytes 2-3: TLV chain length in bytes (8 × number of entries)
- bytes 4-5: modem length in bytes (PCC + PDC)
- bytes 6-7: reserved (0)

Then 8-byte entries: type (2), length of value (2), value (2), padding (2).
The sample writes them in this order:

1. type 1, data type
2. type 2, header status
3. type 7, transaction ID (per-packet counter)
4. type 8, channel
5. types 3 to 6, PCC RSSI2, PCC SNR, PDC RSSI2, PDC SNR (only when metrics are
   available;
6. type 0 padding entries, so that the record has at least 8 entries

Data type values used:

- 1: PCC 40 bit, PDC present
- 2: PCC 80 bit, PDC present
- 3: PCC 40 bit, PDC absent (PDC CRC error)
- 4: PCC 80 bit, PDC absent (PDC CRC error)

## Troubleshooting

- **"target not responding":** check the serial port and the baud rate. The
  board must run this firmware, not the dectnrp-driver sample (it also uses
  the console UART).
- **Wireshark shows packets as "Malformed" or raw data:** check the DLT (304) and
  the dissector version. Packets with an unknown TLV type show an expert warning.
- **Frame CRC errors in the log:** check the cable and the baud rate. The count is
  shown when the capture stops.
- **Two interfaces with similar names:** the real sniffer is *DECT NR+ Sniffer
  (Opener)*. The debug generator is *DECT NR+ Sniffer - DEBUG generator (no hardware)*.
  Use the debug generator only to test the Wireshark setup, not for measurements.
