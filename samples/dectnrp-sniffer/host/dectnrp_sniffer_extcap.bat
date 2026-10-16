@echo off
REM Windows wrapper for the DECT NR+ sniffer extcap (Wireshark only runs .exe/.bat files).
REM Copyright (c) 2026 Deveritec GmbH - SPDX-License-Identifier: Apache-2.0
python "%~dp0dectnrp_sniffer_extcap.py" %*
