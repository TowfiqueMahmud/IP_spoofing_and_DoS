class Packet:
    def __init__(self, source_ip, source_mac, destination_ip, destination_mac = None, payload = None):
        self.source_ip = source_ip
        self.source_mac = source_mac
        self.destination_ip = destination_ip
        if destination_mac:
            self.destination_mac = destination_mac
            self.payload = payload
        else:
            self.type = "ARP req"

    def set_packet_type(self, packet_type):
        self.type = packet_type


class Lan:
    def __init__(self, network_address, network_devices=None):
        self.network_address = network_address
        if network_devices:
            self.network_devices = network_devices
        else:
            self.network_devices = []

    def add_device(self, network_device):
        self.network_devices.append(network_device)
