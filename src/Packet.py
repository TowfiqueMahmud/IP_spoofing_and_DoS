class Packet:
    def __init__(self, source_ip, source_mac, destination_ip, destination_mac = None, payload = None):
        self.source_ip = source_ip
        self.source_mac = source_mac
        self.destination_ip = destination_ip
        if destination_mac:
            self.destination_mac = destination_mac
            self.payload = payload
        else:
            self.destination_mac = ""
            self.payload = ""
            self.type = "ARP req"

    def set_packet_type(self, packet_type):
        self.type = packet_type


    def packet_details(self):
        if self.destination_mac:
            return str(self.source_ip + " " + self.source_mac +
                    " " + self.destination_ip + " " + self.destination_mac +
                    " " + self.type + " " + self.payload)

        return str(self.source_ip + " " + self.source_mac +
                   " " + self.type + " " + self.destination_ip + " " + self.payload)
