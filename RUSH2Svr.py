import socket, array, time
from struct import *

soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def calc_chksum(header):
        chksum = 0
        i = 0
        print(header.hex(' ', -2))
        
        while i + 2 <= len(header):
            hexStr = header[i: i + 2].hex(' ', 1).split(' ')
            hexStr = hexStr[1] + hexStr[0]
            chksum += hexStr_to_int(hexStr)
            i += 2
            
        if i < len(header):
            print(header[i:].hex())
            chksum += hexStr_to_int(header[i:].hex())

        chksum = chksum ^ 0xffff
        return chksum

def hexStr_to_int(hexStr):
    k = 0
    val = 0
    hexVal = {'a': 10, 'b': 11, 'c': 12, 'd': 13, 'e': 14, 'f': 15}
    for i in hexStr[::-1]:
        if i in hexVal:
            val += pow(16, k) * int(hexVal[i])
        else:
            val += pow(16, k) * int(i)

        k += 1

    return val

def is_n_bit_set(bits, n):
    return (bits & (1 << (n - 1))) == (1 << (n - 1))

def create_packet(payload, seq, ack, chksum, flags):
    packet = pack('>4H1464s', seq, ack, chksum, flags, payload.encode())
    return packet

def procc_mess(mess):
    header = mess[0:8]
    #data = mess[8:].decode()
    data = mess[8:]
    
    print("header:", header)
    print("data:", data.decode().rstrip('\x00'))

    packet = []
    packet.append(header)
    #packet.append(data.rstrip('\x00'))
    packet.append(data)

    return packet

def check_flags(data):
    flags = hexStr_to_int(data.hex())

    if is_n_bit_set(flags, 16) and is_n_bit_set(flags, 12):
        print("FIN/ACK")
        return 1

    if is_n_bit_set(flags, 16) and is_n_bit_set(flags, 13):
        print("DAT/ACK")
        return 3

    if is_n_bit_set(flags, 15) and is_n_bit_set(flags, 13):
        print("DAT/NAK")
        return 4

    if is_n_bit_set(flags, 14):
        print("GET")
        return 2

def validate_chk(recvHeader, chksum):
    recvChk = hexStr_to_int(recvHeader[4:6].hex())
    recvFlags = hexStr_to_int(recvHeader[6:].hex())

    if is_n_bit_set(recvFlags, 11) and recvChk != chksum:
        return "INVALID"

    if not is_n_bit_set(recvFlags, 11) and recvChk != 0 and chksum != 0:
        return "INVALID"

def validate_flags(recvHeader, packetType):
    recvFlags = hexStr_to_int(recvHeader[6:].hex()) 

    if packetType == "GET":
        if recvFlags == 8193 or recvFlags == 9217:
            return "VALID"
        else:
            return "INVALID"

    if packetType == "DAT/ACK":
        if recvFlags == 36865 or recvFlags == 37889:
            return "VALID"
        else:
            return "INVALID"

    if packetType == "DAT/NAK":
        if recvFlags == 20481 or recvFlags == 21505:
            return "VALID"
        else:
            return "INVALID"

    if packetType == "FIN/ACK":
        if recvFlags == 34817 or recvFlags == 35841:
            return "VALID"
        else:
            return "INVALID"

def validate_ack(sentSeq, recvHeader, recvAcks):
    recvAck = hexStr_to_int(recvHeader[2:4].hex()) - 1
    try:
        recvAcks[recvAck]
        if recvAcks[recvAck] or sentSeq != recvAck + 1:
            return "INVALID"
    except:
        return "INVALID"

def validate_seq(recvHeader, seq):
    recvSeq = hexStr_to_int(recvHeader[0:2].hex())

    if recvSeq != seq + 1:
        return "INVALID"

def main():
    soc.bind(("localhost", 0))
    print(soc.getsockname()[1], flush=True)
    SO_TIMESTAMPNS = 35
    soc.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
    ack = 0
    seq = 0
    chksum = 0
    packetNo = 0
    packets = []
    getCount = 0
    recvAcks = []
    recvSeq =  0
    lastValidTime = 0
    timestamp = 0

    while True:
        try:
            mess, ancdata, flags, clientAddr = soc.recvmsg(1500, 1500)
            tmp = (unpack("iiii", ancdata[0][2]))
            timestamp = tmp[0] + tmp[2]*1e-10
            
        except socket.timeout:
            print("Resent packet\nPacket number: ", packetNo)
            soc.sendto(packets[packetNo - 1], clientAddr)
            lastValidTime = time.time()
            soc.settimeout(4)
            continue

        print(clientAddr, "connected")
        received = procc_mess(mess)
        type = check_flags(received[0][6:])
        
        if validate_seq(received[0], recvSeq) == "INVALID":
            continue
        else:
            recvSeq = hexStr_to_int(received[0][0:2].hex())

        if type == 1:
            if validate_chk(received[0], chksum) == "INVALID":
                soc.settimeout(lastValidTime + 4 - timestamp)
                recvSeq -= 1
                continue

            if validate_flags(received[0], "FIN/ACK") == "INVALID":
                soc.settimeout(lastValidTime + 4 - timestamp)
                recvSeq -= 1
                continue

            if hexStr_to_int(received[0][2:4].hex()) != seq:
                soc.settimeout(lastValidTime + 4 - timestamp)
                recvSeq -= 1
                continue

            print("ack: ", received[0][0:2].hex())
            finAck = create_packet('', seq + 1, hexStr_to_int(received[0][0:2].hex()), chksum, 34817)
            soc.sendto(finAck, clientAddr)
            soc.close()
            break

        if type == 2:
            if hexStr_to_int(received[0][0:2].hex()) != 1:
                continue

            if hexStr_to_int(received[0][2:4].hex()) != 0:
                continue

            if getCount > 1:
                continue

            if validate_chk(received[0], chksum) == "INVALID":
                continue

            if validate_flags(received[0], "GET") == "INVALID":
                continue

            try:
                file = open(received[1].decode().strip('\x00'), "r")
            except:
                fin = create_packet('', seq + 1, ack, chksum, 2049)
                soc.sendto(fin, clientAddr)
                
            if is_n_bit_set(hexStr_to_int(received[0][6:].hex()), 11):
                chksum = calc_chksum(received[0])

            getCount += 1
            content = file.read()
            i = 0
            while (i + 1464 <= len(content)):
                packet = create_packet(content[i: i + 1464], seq + 1, ack, chksum, 4097)
                packets.append(packet)
                i += 1464
                seq += 1
                recvAcks.append(False)

            if i < len(content):
                packet = create_packet(content[i:] , seq + 1, ack, chksum, 4097)
                seq += 1
                packets.append(packet)
                recvAcks.append(False)

            file.close()
            fin = create_packet('', seq + 1, ack, chksum, 2049)
            seq += 1
            packets.append(fin)
            print("Sent packet\nPacket number: ", packetNo + 1)
            soc.sendto(packets[packetNo], clientAddr)
            packetNo += 1
            soc.settimeout(4)
            lastValidTime = time.time()

        if type == 3:
            if validate_chk(received[0], chksum) == "INVALID":
                soc.settimeout(lastValidTime + 4 - timestamp)
                recvSeq -= 1
                continue
            
            if validate_flags(received[0], "DAT/ACK") == "INVALID":
                soc.settimeout(lastValidTime + 4 - timestamp)
                recvSeq -= 1
                continue

            if validate_ack(packetNo, received[0], recvAcks) == "INVALID":
                soc.settimeout(lastValidTime + 4 - timestamp)
                recvSeq -= 1
                continue

            recvAck = hexStr_to_int(received[0][2:4].hex()) - 1
            recvAcks[recvAck] = True
            
            packet = packets[packetNo]
            print("Sent packet\nPacket number: ", packetNo + 1)
            soc.sendto(packet, clientAddr)
            packetNo += 1
            lastValidTime = time.time()
            soc.settimeout(4)

        if type == 4:
            if validate_chk(received[0], chksum) == "INVALID":
                soc.settimeout(lastValidTime + 4 - timestamp)
                recvSeq -= 1
                continue
            
            if validate_flags(received[0], "DAT/NAK") == "INVALID":
                soc.settimeout(lastValidTime + 4 - timestamp)
                recvSeq -= 1
                continue

            if validate_ack(packetNo, received[0], recvAcks) == "INVALID":
                soc.settimeout(lastValidTime + 4 - timestamp)
                recvSeq -= 1
                continue

            resent = hexStr_to_int(received[0][2:4].hex()) - 1
            packet = packets[resent]
            print("Resent packet\nPacket number: ", packetNo + 1)
            soc.sendto(packet, clientAddr)
            lastValidTime = time.time()
            soc.settimeout(4)

        print('===================')

if __name__ == '__main__':
    main()
