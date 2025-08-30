"""
# AryNetScan 🎯

AryNetScan is a powerful and user-friendly network scanning tool for Windows that allows you to discover devices on your local network with details such as IP address, MAC address, hostname, and vendor. It comes with multiple scan modes, threaded scanning for speed, and features to pause, resume, stop, and copy results.

---

## Features

- Scan your local network using ARP requests.
- Supports multiple scan modes: Fast, Slow, and Custom.
- Discover IP address, MAC address, hostname, and vendor of devices.
- Threaded scanning for high-speed performance.
- Pause, Resume, and Stop scanning anytime.
- Copy selected devices to clipboard.
- Select from available network interfaces.
- Show detailed network interface information (like ipconfig).
- User-friendly GUI built with Tkinter.
- Status updates: shows when scanning, paused, stopped, or completed.

---

## Requirements

- Python 3.x
- Modules:
    - tkinter (usually included with Python)
    - scapy
    - requests
    - concurrent.futures (standard library)

Install required modules via pip if not already installed:

    pip install scapy requests

---

## Usage

1. Run the script as administrator:

    python main.py

2. Select the network interface from the dropdown.
3. Choose the scan mode: Fast, Slow, or Custom.
4. Click Start to begin scanning.
5. Use Pause, Resume, or Stop to control the scan.
6. Click Copy Selected to copy device details to the clipboard.
7. Click Show Network Interfaces to view full ipconfig output.

---

## Notes

- Works only on Windows due to reliance on ipconfig and ARP behavior.
- Vendor lookup uses the public API https://api.macvendors.com.
- For large networks, use Custom mode to adjust thread count.

---

## License

Free to use for learning, testing, and educational purposes. Use responsibly.
"""
