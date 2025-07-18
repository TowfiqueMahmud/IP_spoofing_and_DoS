import tkinter as tk
from tkinter import messagebox, scrolledtext
from functools import partial
from src.Device import AttackerDevice
from Main import Network

# Network Initialization
network = Network(int(input("Enter the number of devices: ")))

# To keep all GUI windows updated in real time
all_device_windows = {}

class DeviceWindow:
    def __init__(self, device):
        self.device = device
        self.root = tk.Toplevel()
        self.root.title(f"Device {device.ip_address}")

        tk.Label(self.root, text=f"Device IP: {device.ip_address}", font=("Arial", 12, "bold")).pack(pady=5)

        # Buttons
        self.arp_entry = self._labeled_entry("Destination IP for ARP:")
        tk.Button(self.root, text="Send ARP", command=self.send_arp).pack(fill='x', pady=2)

        self.normal_ip_entry = self._labeled_entry("Destination IP for Normal Packet:")
        self.payload_entry = self._labeled_entry("Payload:")
        tk.Button(self.root, text="Send Normal", command=self.send_normal).pack(fill='x', pady=2)

        if isinstance(device, AttackerDevice):
            self.spoof_target_entry = self._labeled_entry("Target IP:")
            self.spoof_victim_entry = self._labeled_entry("Victim IP:")
            tk.Button(self.root, text="Spoof", command=self.spoof).pack(fill='x', pady=2)

        tk.Button(self.root, text="Receive", command=self.receive).pack(fill='x', pady=2)

        # Output box
        self.output_box = scrolledtext.ScrolledText(self.root, height=20, width=60)
        self.output_box.pack(pady=10)

        self.refresh_output()
        all_device_windows[self.device.ip_address] = self

    def _labeled_entry(self, label_text):
        tk.Label(self.root, text=label_text).pack()
        entry = tk.Entry(self.root)
        entry.pack()
        return entry

    def refresh_output(self):
        self.output_box.delete(1.0, tk.END)
        self.output_box.insert(tk.END, f"IP: {self.device.ip_address}\n")
        self.output_box.insert(tk.END, f"MAC: {self.device.mac_address}\n")
        self.output_box.insert(tk.END, f"Connections: {self.device.active_connections}/{self.device.max_connections}\n")
        self.output_box.insert(tk.END, "Address Table:\n")
        for ip, mac in self.device.address_table.items():
            self.output_box.insert(tk.END, f"  {ip} -> {mac}\n")
        self.output_box.insert(tk.END, "Received Packets:\n")
        for pkt in self.device.received_packets:
            self.output_box.insert(tk.END, f"  {pkt.packet_details()}\n")

    def send_arp(self):
        dest_ip = self.arp_entry.get()
        packet = self.device.packet_build(dest_ip, "ARP req")
        if packet:
            self.device.send_packet(packet)
            self.arp_entry.delete(0, tk.END)  # Clear input
            self._broadcast_update(f"{self.device.ip_address} sent ARP to {dest_ip}")
        else:
            messagebox.showerror("Error", "ARP packet creation failed.")

    def send_normal(self):
        dest_ip = self.normal_ip_entry.get()
        payload = self.payload_entry.get()
        packet = self.device.packet_build(dest_ip, "Normal packet", payload)
        if packet:
            self.device.send_packet(packet)
            self.normal_ip_entry.delete(0, tk.END)  # Clear destination IP
            self.payload_entry.delete(0, tk.END)  # Clear payload
            self._broadcast_update(f"{self.device.ip_address} sent normal packet to {dest_ip}")
        else:
            messagebox.showerror("Error", f"MAC for {dest_ip} unknown. Run ARP first.")

    def spoof(self):
        target_ip = self.spoof_target_entry.get()
        victim_ip = self.spoof_victim_entry.get()
        victim = network.get_device_by_ip(victim_ip)
        if victim:
            packet = self.device.spoofed_packet_build(target_ip, victim_ip, victim)
            if packet:
                self.device.send_packet(packet)
                self.spoof_target_entry.delete(0, tk.END)
                self.spoof_victim_entry.delete(0, tk.END)
                self._broadcast_update(f"{self.device.ip_address} spoofed {victim_ip} to {target_ip}")
            else:
                messagebox.showerror("Error", "Spoofing failed. Victim MAC not known.")

    def receive(self):
        self.device.receive_packet()
        self._broadcast_update(f"{self.device.ip_address} received packets")

    def _broadcast_update(self, action_msg):
        for win in all_device_windows.values():
            win.refresh_output()
        print(action_msg)


class LanApp:
    def __init__(self, network):
        self.network = network
        self.root = tk.Tk()
        self.root.title("LAN Simulator")

        # Scrollable Frame
        canvas = tk.Canvas(self.root, height=500, width=400)
        scrollbar = tk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas)

        scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        tk.Label(scroll_frame, text=f"LAN Network Address: {network.lan.network_address}", font=("Helvetica", 14)).pack(pady=10)

        for dev in network.devices:
            btn = tk.Button(scroll_frame, text=f"{dev.ip_address}", width=30, command=partial(self.open_device, dev))
            btn.pack(pady=2)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.root.mainloop()

    def open_device(self, device):
        if device.ip_address in all_device_windows:
            win = all_device_windows[device.ip_address]
            win.root.lift()
        else:
            DeviceWindow(device)


if __name__ == '__main__':
    LanApp(network)
