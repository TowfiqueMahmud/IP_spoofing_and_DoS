import random
from src.Structure import Packet

class NetworkDevice:
    def __init__(self, ip_address, mac_address, max_connections=100):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.max_connections = max_connections
        self.active_connections = 5
        self.received_packets = []
        self.address_table = []

    def packet_build(self, destination_ip, packet_type, payload = None):

        if packet_type == "ARP req":
            packet = Packet(self.ip_address, self.mac_address, destination_ip)

        else:
            destination_mac = self.address_table[destination_ip]
            packet = Packet(self.ip_address, self.mac_address, destination_ip, destination_mac, payload)
            packet.set_packet_type(packet_type)

        return packet

    def accept_connection(self, packet):
        if self.active_connections >= self.max_connections:
            print(f"[{self.ip_address}] Connection rejected: Max capacity reached.")
            return False

        self.received_packets.append(packet)
        self.active_connections += 1
        print(f"[{self.ip_address}] Accepted packet from {packet['src']}")
        return True

    def reset_connections(self):
        self.active_connections = 0
        print(f"[{self.ip_address}] Connections reset.")

    def __str__(self):
        return f"<Device {self.ip_address} ({self.active_connections}/{self.max_connections} connections)>"


class AttackerDevice(NetworkDevice):
    def __init__(self, ip_address, mac_address, max_connections=100):
        super().__init__(ip_address, mac_address, max_connections)

    def spoofed_packet_build(self, fake_src_ip, destination_ip, payload="Attack"):
        destination_mac = self.address_table[destination_ip]
        packet = Packet(fake_src_ip, self.mac_address, destination_ip, destination_mac, payload)
        packet.set_packet_type("ARP res")
        return packet

