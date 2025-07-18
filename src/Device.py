from src.Packet import Packet


class NetworkDevice:
    def __init__(self, ip_address, mac_address, max_connections=100):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.max_connections = max_connections
        self.active_connections = 5
        self.received_packets = []
        self.address_table = {}
        self.lan = None

    def print_device_details(self):
        print("IP address: " + self.ip_address)
        print("MAC address: " + self.mac_address)
        print("Connections: " + str(self.active_connections) + "/" + str(self.max_connections))
        print("Address table:")
        for entry in self.address_table:
            print("\tIP address: " + entry + "\tMAC address: " + self.address_table[entry])
        print("Queued packets:")
        for i in range(len(self.received_packets)):
            print("\t" + self.received_packets[i].packet_details())

    def packet_build(self, destination_ip, packet_type, payload = None):

        if packet_type == "ARP req":
            packet = Packet(self.ip_address, self.mac_address, destination_ip)

        else:
            if destination_ip in self.address_table:
                destination_mac = self.address_table[destination_ip]
            else:
                print("IP address " + destination_ip + " not found in address table")
                return None
            if destination_mac is None:
                print(f"[{self.ip_address}] MAC address for {destination_ip} not found. ARP request needed.")
                return None  # Caller should handle ARP request
            packet = Packet(self.ip_address, self.mac_address, destination_ip, destination_mac, payload)
            packet.set_packet_type(packet_type)

        return packet

    def set_lan(self, lan:"Lan"):
        self.lan = lan

    def send_packet(self, packet:Packet):
        if packet.type == "Normal packet" or packet.type == "ARP res":

            for entry in self.address_table:

                if self.address_table[entry] == packet.destination_mac:
                    dest = self.lan.get_device(packet.destination_mac)

                    if dest:
                        dest.received_packets.append(packet)
                        return True

                    print("No destination device found")
                    return False

            print("No such device in address table, send ARP request first")
            return False

        else:
            self.lan.broadcast(packet)
            return True

    def receive_packet(self):
        if not self.received_packets:
            return

        temp = self.received_packets.pop(0)

        if temp.type == "ARP req":
            # Responding to ARP request
            if temp.destination_ip == self.ip_address:
                self.address_table[temp.source_ip] = temp.source_mac
                response = self.packet_build(temp.source_ip, "ARP res", "Responding to ARP request")
                if response:
                    self.send_packet(response)

        elif temp.type == "ARP res":
            if temp.source_ip not in self.address_table:
                self.address_table[temp.source_ip] = temp.source_mac
                print("A device added successfully!")
            else:
                print("A device with same ip already exists, so packet dropped")

        else:
            print("A packet received from " + temp.source_ip +
                  "\nThe message: " + temp.payload)

        if len(self.address_table) > 5:         #An arbitrary number showing the small cache size of network devices
            self.address_table.pop(next(iter(self.address_table)))

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


class AttackerDevice(NetworkDevice):
    def __init__(self, ip_address, mac_address, max_connections=100):
        super().__init__(ip_address, mac_address, max_connections)

    def receive_packet_for_spoofing(self):
        arp_packets = []
        for packet in self.received_packets:
            if packet.type == "ARP req":
                arp_packets.append(packet)
        return arp_packets

    def spoofed_packet_build(self, fake_src_ip, destination_ip, victim:NetworkDevice, payload="Attack"):
        destination_mac = ""
        for arp_packet in self.receive_packet_for_spoofing():
            if arp_packet.source_ip == victim.ip_address:
                destination_mac = arp_packet.source_mac
                self.address_table[victim.ip_address] = destination_mac
                self.received_packets.remove(arp_packet)
        if destination_mac == "":
            print(f"[{self.ip_address}] Cannot spoof: destination MAC unknown for IP {destination_ip}")
            return None
        packet = Packet(fake_src_ip, self.mac_address, destination_ip, destination_mac, payload)
        packet.set_packet_type("ARP res")
        return packet


class Lan:
    def __init__(self, network_address, network_devices=None):
        self.network_address = network_address
        if network_devices:
            self.network_devices = network_devices
        else:
            self.network_devices = []

    def add_device(self, network_device:NetworkDevice):
        self.network_devices.append(network_device)

    def get_device(self, mac_address):
        for device in self.network_devices:
            if mac_address == device.mac_address:
                return device
        return None

    def broadcast(self, packet:Packet):
        for device in self.network_devices:
            if device.ip_address == packet.source_ip:
                continue
            device.received_packets.append(packet)