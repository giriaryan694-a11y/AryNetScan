# ------------------- Imports -------------------
import socket
import threading
import subprocess
from scapy.all import ARP, Ether, srp
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import requests
from concurrent.futures import ThreadPoolExecutor
import time
import re
from queue import Queue

# ------------------- Thread Events -------------------
pause_event = threading.Event()
stop_event = threading.Event()
result_queue = Queue()

# ------------------- Utility -------------------
def parse_ipconfig():
    """Parse ipconfig output to get adapters with IPv4"""
    output = subprocess.check_output("ipconfig", shell=True, text=True, encoding="utf-8", errors="ignore")
    adapters = []
    current_adapter = None
    ipv4 = None
    subnet = None
    gateway = None

    for line in output.splitlines():
        line = line.strip()
        if line.endswith(":") and ("adapter" in line.lower()):
            if current_adapter and ipv4:
                adapters.append((current_adapter, ipv4, subnet, gateway))
            current_adapter = line
            ipv4 = subnet = gateway = None
        elif "IPv4 Address" in line:
            ipv4 = line.split(":")[-1].strip()
        elif "Subnet Mask" in line:
            subnet = line.split(":")[-1].strip()
        elif "Default Gateway" in line:
            gateway = line.split(":")[-1].strip()

    if current_adapter and ipv4:
        adapters.append((current_adapter, ipv4, subnet, gateway))

    return adapters, output

def get_ip_range_for_ip(ip):
    try:
        base_ip = '.'.join(ip.split('.')[:-1])
        return [f"{base_ip}.{i}" for i in range(1, 255)]
    except:
        return []

# ------------------- Vendor lookup -------------------
def get_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=2)
        return response.text
    except:
        return "Unknown"

# ------------------- Scanning -------------------
def scan_ip(ip, delay=0):
    if stop_event.is_set():
        return
    pause_event.wait()

    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    try:
        result = srp(packet, timeout=1, verbose=0)[0]
        for _, received in result:
            try:
                hostname = socket.gethostbyaddr(received.psrc)[0]
            except:
                hostname = "Unknown"
            device = {
                'ip': received.psrc,
                'mac': received.hwsrc,
                'hostname': hostname,
                'vendor': get_vendor(received.hwsrc)
            }
            result_queue.put(device)
        time.sleep(delay)
    except:
        pass

def update_tree():
    while not result_queue.empty():
        device = result_queue.get()
        tree.insert('', 'end', values=(device['ip'], device['mac'], device['hostname'], device['vendor']))
    root.after(500, update_tree)

def scan_network_threaded(mode="Fast"):
    selected = iface_dropdown.get()
    if not selected:
        messagebox.showerror("No Interface", "Please select an interface first.")
        return

    m = re.search(r"IPv4: ([0-9.]+)", selected)
    if not m:
        messagebox.showerror("Error", "Could not parse IP from selected interface.")
        return
    selected_ip = m.group(1)
    ip_list = get_ip_range_for_ip(selected_ip)
    if not ip_list:
        messagebox.showerror("Error", f"Could not get IP range for {selected_ip}")
        return

    scan_button.config(state=tk.DISABLED)
    stop_event.clear()
    pause_event.set()
    tree.delete(*tree.get_children())
    status_label.config(text="Scanning...")  # <-- Start scanning

    if mode == "Fast":
        thread_count = 100
        delay = 0
    elif mode == "Slow":
        thread_count = 20
        delay = 0.8
    elif mode == "Custom":
        try:
            thread_count = int(simpledialog.askstring("Threads", "Enter number of threads (1-500):"))
            if not 1 <= thread_count <= 500:
                raise ValueError
        except:
            messagebox.showerror("Invalid Input", "Invalid thread count. Using 50.")
            thread_count = 50
        delay = 0.3
    else:
        thread_count = 50
        delay = 0.3

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        for ip in ip_list:
            if stop_event.is_set():
                break
            executor.submit(scan_ip, ip, delay)

    scan_button.config(state=tk.NORMAL)
    duration = round(time.time() - start_time, 2)
    if stop_event.is_set():
        status_label.config(text="Scan Stopped")
        messagebox.showinfo("Scan Stopped", f"The scan was stopped manually after {duration} seconds.")
    else:
        total = len(tree.get_children())
        status_label.config(text="Scan Completed")  # <-- Scan completed
        messagebox.showinfo("Scan Completed", f"Scan finished in {duration} seconds.\nDevices Found: {total}")

# ------------------- Show Interfaces Popup -------------------
def show_interfaces_popup():
    adapters, raw_output = parse_ipconfig()
    top = tk.Toplevel(root)
    top.title("Available Network Interfaces")
    text = tk.Text(top, wrap="word", bg="#111", fg="white")
    text.pack(fill="both", expand=True)
    text.insert("1.0", raw_output)
    text.config(state="disabled")
    top.geometry("800x500")

# ------------------- Copy Selected Devices -------------------
def copy_selected_devices():
    selected_items = tree.selection()
    if not selected_items:
        return
    copied_text = ""
    for item in selected_items:
        values = tree.item(item, 'values')
        copied_text += f"IP: {values[0]}, MAC: {values[1]}, Vendor: {values[3]}\n"
    root.clipboard_clear()
    root.clipboard_append(copied_text.strip())
    messagebox.showinfo("Copied", "Selected devices copied to clipboard.")

# ------------------- GUI -------------------
root = tk.Tk()
root.title("Aryan's LAN Scanner 🎯")
root.geometry("860x650")
root.configure(bg="#111")

scan_mode = tk.StringVar(value="Fast")

style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background="#222", foreground="#fff", rowheight=25, fieldbackground="#111")
style.configure("Treeview.Heading", background="#333", foreground="white")

# Status label
status_label = tk.Label(root, text="Idle", bg="#111", fg="white", font=("Arial", 12, "bold"))
status_label.pack(pady=5)

columns = ("IP Address", "MAC Address", "Hostname", "Vendor")
tree = ttk.Treeview(root, columns=columns, show='headings')
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=180)
tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Buttons
btn_frame = tk.Frame(root, bg="#111")
btn_frame.pack(pady=10)

scan_button = tk.Button(btn_frame, text="▶ Start", command=lambda: threading.Thread(target=scan_network_threaded, args=(scan_mode.get(),), daemon=True).start(), bg="#444", fg="white", width=10)
pause_button = tk.Button(btn_frame, text="⏸ Pause", command=lambda: pause_event.clear(), bg="#555", fg="white", width=10)
resume_button = tk.Button(btn_frame, text="▶ Resume", command=lambda: pause_event.set(), bg="#666", fg="white", width=10)
stop_button = tk.Button(btn_frame, text="⏹ Stop", command=lambda: [stop_event.set(), pause_event.set(), scan_button.config(state=tk.NORMAL)], bg="#800", fg="white", width=10)
copy_button = tk.Button(btn_frame, text="📋 Copy Selected", command=copy_selected_devices, bg="#228", fg="white", width=14)

scan_button.grid(row=0, column=0, padx=6)
pause_button.grid(row=0, column=1, padx=6)
resume_button.grid(row=0, column=2, padx=6)
stop_button.grid(row=0, column=3, padx=6)
copy_button.grid(row=0, column=4, padx=6)

# Mode
mode_label = tk.Label(root, text="Scan Mode:", bg="#111", fg="white", font=("Arial", 10, "bold"))
mode_label.pack()
mode_dropdown = ttk.Combobox(root, textvariable=scan_mode, values=["Fast", "Slow", "Custom"], state="readonly")
mode_dropdown.pack(pady=5)
mode_dropdown.current(0)

# Interface dropdown
iface_label = tk.Label(root, text="Select Interface:", bg="#111", fg="white", font=("Arial", 10, "bold"))
iface_label.pack()

adapters, _ = parse_ipconfig()
iface_values = [f"{a[0]} | IPv4: {a[1]} | Subnet: {a[2]} | Gateway: {a[3]}" for a in adapters]
iface_dropdown = ttk.Combobox(root, values=iface_values, state="readonly")
iface_dropdown.pack(pady=5)
if iface_values:
    iface_dropdown.current(0)

# Show network info button
tk.Button(root, text="Show Network Interfaces (ipconfig)", bg="#444", fg="white", font=("Arial", 10, "bold"), command=show_interfaces_popup).pack(pady=5)

# Start updating Treeview from queue
root.after(500, update_tree)

root.mainloop()
