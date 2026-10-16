# Wireshark


## Build development release for linux

The DECT-NR-TAP record (`LINKTYPE_DECT_NR_TAP`, DLT 304) is part of the development release v4.7.4 of wireshark.
[packet-dect-nr-tap.c](https://gitlab.com/wireshark/wireshark/-/blob/v4.7.4/epan/dissectors/packet-dect-nr-tap.c?ref_type=tags)
[DSRCorporation/dect-nr-tap](https://github.com/DSRCorporation/dect-nr-tap)

```shell
# 1. Download and extract the source code
wget https://2.na.dl.wireshark.org/src/wireshark-4.7.4.tar.xz
tar xf wireshark-4.7.4.tar.xz
cd wireshark-4.7.4

# 2. Install build dependencies (install-optional or install-deb-deps)
sudo tools/os_setup/debian-setup.sh --install-deb-deps

# 3. Configure, build, install (default destination: /usr/local)
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j"$(nproc)"
sudo cmake --install build
sudo ldconfig

# 4. checks version and whether DECT NR+ / TAP is present
wireshark -v
tshark -G protocols | grep -i dect

# 5. Grant permissions for live capture (one-time):
sudo groupadd -f wireshark
sudo usermod -aG wireshark,dialout "$USER"
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/dumpcap
```


## Install Excap

Wireshark looks for **extcap** plugins in specific default directories depending on your operating system, or you can find your exact path directly inside the application.

How to Find Your Exact Extcap Path in Wireshark

1. Open Wireshark.
2. Go to the top menu and select **Help** → **About Wireshark**.
3. Click on the **Folders** tab.
4. Look for **Extcap path** (or **Personal Extcap Path** for user-specific plugins) and click the path to open it.
5. copy `dectnrp_sniffer_extcap.py` and `dectnrp_sniffer_extcap.bat` for windows to the extcap-folder (~/.local/lib/wireshark/extcap)

