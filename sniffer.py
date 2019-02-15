import socket
import struct
import binascii


def udp_analyser(data):
    snif_dat = struct.unpack('!4H', data[:8])
    print "===============UDP Header Information============="
    print "Source port: \t", (snif_dat[0])
    print "Destination port: \t", (snif_dat[1])
    print "Length: \t", (snif_dat[2])
    print "Checksum: \t", (snif_dat[3])
    data = data[8:]
    return data


def tcp_analyser(data):
    snif_dat = struct.unpack('!2H2I4H', data[:20])
    print "===============TCP Header Information============="
    print "Source port: \t", (snif_dat[0])
    print "Destination port: \t", (snif_dat[1])
    print "Sequence number: \t", (snif_dat[2])
    print "Acknowledgement number: \t", (snif_dat[3])
    print "Data Offset: \t", (snif_dat[4] >> 12)
    print "Reserved: \t", ((snif_dat[4] >> 6) & 0x03f)
    print "Urgent Flag: \t", ((snif_dat[4] >> 5) & 0x001)
    print "Acknowledgement flag: \t", ((snif_dat[4] >> 4) & 0x001)
    print "Push Flag: \t", ((snif_dat[4] >> 3) & 0x0001)
    print "Reset flag: \t", ((snif_dat[4] >> 2) & 0x0001)
    print "SYN flag: \t", ((snif_dat[4] >> 1) & 0x0001)
    print "FIN flag: \t", (snif_dat[4] & 0x0001)
    print "Window: \t", (snif_dat[5])
    print "Checksum: \t", (snif_dat[6])
    print "Urgent Pointer: \t", (snif_dat[7])
    print "=================================================="
    data = data[20:]
    return data


def l3_analyser(data):
    no_op_bool = False
    snif_dat = struct.unpack('!6H4s4s', data[:20])
    print "==============Layer 3 Information=========="
    print "Version: \t", (snif_dat[0] >> 12)
    print "Internet Header Length: \t", ((snif_dat[0] >> 8) & 0x0f)
    if ((snif_dat[0] >> 8) & 0x0f) == 5:
        no_op_bool = True
    print "Type of Service: \t", ((snif_dat[0]) & 0x00ff)
    print "Total Length: \t", (snif_dat[1])
    print "Identification: \t", (snif_dat[2])
    print "Reserved flag: \t", (snif_dat[3] >> 15)
    print "Do not Fragment flag: \t", ((snif_dat[3] >> 14) & 0x1)
    print "More Fragment flag: \t", ((snif_dat[3] >> 13) & 0x1)
    print "Fragment Offset: \t", ((snif_dat[3]) & 0x1fff)
    print "Time to Live: \t", (snif_dat[4] >> 8)
    l4_protocol_code = (snif_dat[4]) & 0x00ff
    if l4_protocol_code == 6:
        print "Layer 4 protocol: \tTCP"
    elif l4_protocol_code == 17:
        print "Layer 4 protocol: \tUDP"
    print "Checksum: \t", (snif_dat[5])
    print "Source address: \t", (socket.inet_ntoa(snif_dat[6]))
    print "Destination address: \t", (socket.inet_ntoa(snif_dat[7]))
    print "==========================================="
    data = data[20:]

    return l4_protocol_code, data, no_op_bool


def l2_analyser(data):
    l3_bool = False
    snif_dat = struct.unpack('!6s6sH', data[:14])
    print "=============Layer 2 Information==========="
    print "Destination MAC address: \t", binascii.hexlify(snif_dat[0])
    print "Source MAC address: \t", binascii.hexlify((snif_dat[1]))
    print "Layer 3 protocol: \t", hex(snif_dat[2])
    print "==========================================="
    data = data[14:]
    if hex(snif_dat[2]) == '0x800':
        l3_bool = True
    return data, l3_bool


def main():
    while True:
        print "\n\n\n\n\n"
        sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x003))
        data, l3_bool = l2_analyser(sock.recv(2048))
        if l3_bool:
            l4_proto_code, data, no_op_bool = l3_analyser(data)
            if no_op_bool:
                if l4_proto_code == 6:
                    data = tcp_analyser(data)
                elif l4_proto_code == 17:
                    data = udp_analyser(data)
    return


main()
