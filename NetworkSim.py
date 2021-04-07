import socket, sys, struct, threading

soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

class host:
    def __init__(self, ip, llAddr):
        self.ip = ip
        self.llAddr = llAddr
        self.gwIP = None
        self.range = int(ip[ip.find("/") + 1:])
        self.network = ""
        self.arpTable = {}
        self.revArp = {}
        self.mask = ""
        self.mtu = 1500
        self.frto = 5

    def set_ip_addr(self, ip):
        self.ip = ip

    def set_ll_addr(self, llAddr):
        self.llAddr = llAddr

    def get_ip(self):
        return self.ip

    def get_ll_addr(self):
        return self.llAddr

    def set_gwIP(self, gwIP):
        self.gwIP = gwIP

    def get_gwIP(self):
        return self.gwIP

    def get_mask(self, r):
        mask = ""
        for i in range(32):
            if i >= r:
                mask += "0"
            else:
                mask += "1"
            if i % 8 == 7 and i < 31:
                mask += "."
        bits = mask.split(".")

        mask = ""
        for i in range(4):
            mask += str(int(bits[i], 2)) + "."

        return mask[:len(mask) - 1]

    def calc_network(self):
        ipbytes = self.ip[:self.ip.find("/")].split(".")
        self.mask = self.get_mask(self.range)

        tmpMask = self.mask.split(".")
        for i in range(4):
            bite = int(tmpMask[i]) & int(ipbytes[i])
            self.network += str(bite) + "."

        self.network = self.network[:len(self.network) - 1]

    def add_entry(self, ip, port):
        self.arpTable[ip] = port
        self.revArp[port] = ip

    def get_entry(self, ip):
        return self.arpTable.get(ip)

    def get_subnet_mask(self):
        return self.mask

    def get_network(self):
        return self.network

    def get_mtu(self):
        return self.mtu

    def set_mtu(self, mtu):
        self.mtu = mtu

    def get_frto(self):
        return self.frto

    def set_frto(self, frto):
        self.frto = frto

class IP4Packet:
    def __init__(self, dst, src, payload, flag = 0, offset = 0):
        self.dst = dst
        self.src = src
        self.packet = None
        self.payload = payload
        self.ip_flg = (flag << 13) + offset
        self.create_ipv4_fields_list()

    def create_ipv4_fields_list(self):

        ip_ver = 4
        ip_vhl = 5

        self.ip_ver = (ip_ver << 4 ) + ip_vhl

        ip_dsc = 0
        ip_ecn = 0

        self.ip_dfc = (ip_dsc << 2 ) + ip_ecn

        self.ip_tol = 0

        self.ip_idf = self.ip_flg

        ip_rsv = 0

        self.ip_ttl = 255

        self.ip_protocol = 0

        self.ip_chk = 0

        self.ip_saddr = socket.inet_aton(self.src)

        self.ip_daddr = socket.inet_aton(self.dst)

        return

    def assemble_ipv4_fields(self, length):
        self.packet = struct.pack('!BBHHHBBH4s4s{}s'.format(length),
            self.ip_ver,
            self.ip_dfc,
            self.ip_tol,
            self.ip_idf,
            self.ip_flg,
            self.ip_ttl,
            self.ip_protocol,
            self.ip_chk,
            self.ip_saddr,
            self.ip_daddr,
            self.payload.encode()
        )

    def get_packet(self):
        return self.packet

class ClientThread(threading.Thread):
    def __init__(self,soc, host):
        threading.Thread.__init__(self)
        self.soc = soc
        self.host = host
        self.packet = None

    def run(self):
        while True:
            try:
                self.packet = self.soc.recv(self.host.get_mtu())
                payloadLen = len(self.packet) - 20
                data = struct.unpack("!BBHHHBBH4s4s{}s".format(payloadLen), self.packet)
                fragments = ''
                if data[4] & (1 << 13):
                    offset = data[4] & ((1 << 13) - 1)
                    if not offset:
                        fragments += data[10].decode()
                    else:
                        fragments = fragments[:offset] + data[10].decode() + fragments[offset:]
                    continue
                else:
                    fragments += data[10].decode()

                protocol = data[6]
                saddr = socket.inet_ntoa(data[8])
                #message = data[10].decode()
                msgProtocol4 ="\x08\x08Message received from {}: \"{}\""
                msgProtocol = "\x08\x08Message received from {} with protocol 0x{}"

                if not protocol:
                    print(msgProtocol4.format(saddr, fragments), end="\n> ", flush=True)
                else:
                    p = "0"
                    if protocol < 10:
                        p += str(protocol)
                    else:
                        p = str(protocol)

                    print(msgProtocol.format(saddr, p), end="\n> ", flush=True)
            except:
                return

def proc_gw(arg, host):
    if arg[0] == "set":
        host.set_gwIP(arg[1])

    elif arg[0] == "get":
        print(host.get_gwIP(), flush=True)

def proc_arp(arg, host):
    if arg[0] == "set":
        host.add_entry(arg[1], arg[2])

    elif arg[0] == "get":
        print(host.get_entry(arg[1]), flush=True)

def part_of_network(ip, subnet, mask):
    ipBytes = ip.split(".")
    maskBytes = mask.split(".")
    network = ""

    for i in range(4):
        bite = int(maskBytes[i]) & int(ipBytes[i])
        network += str(bite) + "."

    network = network[:len(network) - 1]
    if network == subnet:
        return True

    return False

def sent_mess(arg, host, soc):
    dest = arg[0]
    sentTo = dest
    if not part_of_network(dest, host.get_network(), host.get_subnet_mask()):

        if host.get_gwIP() == None:
            print("No gateway found", flush=True)
            return

        sentTo = host.get_gwIP()

    if host.get_entry(sentTo) == None:
        print("No ARP entry found", flush=True)
        return

    src = host.get_ip()[:host.get_ip().find("/")]
    port = host.get_entry(dest)
    payload = arg[1].strip('\"')
    length = len(payload)

    if length <= (host.get_mtu() - 20):
        mess = IP4Packet(dest, src, payload)
        mess.assemble_ipv4_fields(length)
        soc.sendto(mess.get_packet(), ("localhost", int(host.get_entry(sentTo))))
    else:
        end = 0
        for i in range(length // (host.get_mtu() - 20)):
            length = host.get_mtu() - 20
            start = i * length
            end = (i+1) * length
            fragment = payload[start:end]
            mess = IP4Packet(dest, src, fragment, 1, start)
            mess.assemble_ipv4_fields(length)
            soc.sendto(mess.get_packet(), ("localhost", int(host.get_entry(sentTo))))
        
        fragment = payload[end:]
        length = len(fragment)
        mess = IP4Packet(dest, src, fragment, 0, end)
        mess.assemble_ipv4_fields(length)
        soc.sendto(mess.get_packet(), ("localhost", int(host.get_entry(sentTo)))) 

def proc_mtu(arg, host):
    if arg[0] == "set":
        host.set_mtu(int(arg[1]))

    elif arg[0] == "get":
        print(host.get_mtu(), flush=True)

def proc_frto(arg, host):
    if arg[0] == "set":
        host.set_frto(int(arg[1]))

    elif arg[0] == "get":
        print(host.get_frto(), flush=True)

def proc_cmd(args, host, soc):
    cmd = list(args.split(" "))
    if cmd[0] == "gw":
        proc_gw(cmd[1:], host)
    elif cmd[0] == "arp":
        proc_arp(cmd[1:], host)
    elif cmd[0] == "msg":
        sent_mess(cmd[1:], host, soc)
    elif cmd[0] == "mtu":
        proc_mtu(cmd[1:], host)
    elif cmd[0] == "frto":
        proc_frto(cmd[1:], host)

def main():
    h = host(sys.argv[1], int(sys.argv[2]))
    h.calc_network()
    soc.bind(("localhost", h.get_ll_addr()))
    cThread = ClientThread(soc, h)
    cThread.start()

    while True:
        userInput = input("> ")
        
        if userInput == "exit":
            cThread.join()
            soc.close()
            return

        proc_cmd(userInput, h, soc)

    return

if __name__ == '__main__':
    main()
