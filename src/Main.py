from src.Device import NetworkDevice, AttackerDevice, Lan

class Network:
    def __init__(self, device_count):
        self.lan = Lan("192.168.0.0")
        self.devices = []

        for i in range(1, device_count):
            ip = f"192.168.0.{i}"
            mac = f"dd:ee:aa:bb:00:{i:02x}"
            dev = NetworkDevice(ip, mac)
            dev.set_lan(self.lan)
            self.lan.add_device(dev)
            self.devices.append(dev)

        attacker_ip = "192.168.0.254"
        attacker_mac = "aa:bb:cc:dd:ee:ff"
        attacker = AttackerDevice(attacker_ip, attacker_mac)
        attacker.set_lan(self.lan)
        self.lan.add_device(attacker)
        self.devices.append(attacker)

    def get_device_by_ip(self, ip_address):
        for device in self.devices:
            if device.ip_address == ip_address:
                return device
        return None

def print_all_devices(net:Network):
    for d in net.devices:
        d.print_device_details()

if __name__ == "__main__":
    count = int(input("Enter the number of device: "))
    test_lan = Network(count)
    userIP = "lan"
    current = None
    while (True):
        command = input(userIP + ":~$ ")
        args = command.split(" ")

        if args[0] == "show":
            if userIP == "lan":
                if len(args) != 2:
                    print("Invalid command")

                else:
                    if args[1] == "all":
                        print_all_devices(test_lan)
                    else:
                        if test_lan.get_device_by_ip(args[1]):
                            test_lan.get_device_by_ip(args[1]).print_device_details()
                        else:
                            print("No such device found")


            else:
                if len(args) == 1:
                    current.print_device_details()
                else:
                    print("Invalid command")

        elif args[0] == "change-ip":
            if len(args) != 2:
                print("Invalid command")
            else:
                if args[1] == "lan":
                    userIP = "lan"
                    current = None
                elif test_lan.get_device_by_ip(args[1]):
                    current = test_lan.get_device_by_ip(args[1])
                    userIP = args[1]
                else:
                    print("No such device found")

        elif args[0] == "send":
            if args[1] == "arp":
                destination = test_lan.get_device_by_ip(args[2])
                if destination:
                    packet = current.packet_build(args[2], "ARP req", "This is an ARP request")
                    current.send_packet(packet)

            elif args[1] == "normal":
                destination = test_lan.get_device_by_ip(args[2])
                if destination:
                    packet = current.packet_build(args[2], "Normal packet", args[3])
                    if packet:
                        current.send_packet(packet)
                    else:
                        print("Unable to build packet")

        elif args[0] == "receive":
            if len(args) > 1:
                print("Invalid command")
            else:
                current.receive_packet()


        elif args[0] == "spoof":
            if not isinstance(current, AttackerDevice):
                print("Invalid command")

            else:
                packet = current.spoofed_packet_build(args[1], args[2],
                                                      test_lan.get_device_by_ip(args[2]), "Attacking you haha")
                current.send_packet(packet)

        else:
            print("Invalid command")
