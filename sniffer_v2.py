import socket
import struct
import binascii


def printer(data):
    file_obj = open('trace_file.txt', 'a')
    file_obj.write(data)
    file_obj.close()
    return


def tcp(data):
    sniff = struct.unpack('!2H2I4H', data[:20])
    data = data[20:]
    printer("==================TCP Header=================\n")
    printer("Source port: \t" + str(sniff[0]) + '\n')
    printer("Destination port: \t" + str(sniff[1]) + '\n')
    printer("Sequence number: \t" + str(sniff[2]) + '\n')
    printer("Acknowledgement number: \t" + str(sniff[3]) + '\n')
    if (sniff[4] >> 12) == 5:
        printer("Data Offset: \t" + str(sniff[4] >> 12) + '\n')
    else:
        printer("Data Offset: \t" + str(sniff[4] >> 12) + '\n')
        printer("This Header has Option Field\n")
    printer("Reserved: \t" + str((sniff[4] >> 6) & 0x03f) + '\n')
    printer("Urgent Flag: \t" + str((sniff[4] >> 5) & 0x001) + '\n')
    printer("Acknowledgement flag: \t" + str((sniff[4] >> 4) & 0x001) + '\n')
    printer("Push Flag: \t" + str((sniff[4] >> 3) & 0x0001) + '\n')
    printer("Reset flag: \t" + str((sniff[4] >> 2) & 0x0001) + '\n')
    printer("SYN flag: \t" + str((sniff[4] >> 1) & 0x0001) + '\n')
    printer("FIN flag: \t" + str(sniff[4] & 0x0001) + '\n')
    printer("Window: \t" + str(sniff[5]) + '\n')
    printer("Checksum: \t" + str(sniff[6]) + '\n')
    printer("Urgent Pointer: \t" + str(sniff[7]) + '\n')
    printer("=============================================\n")
    return data


def udp(data):
    sniff = struct.unpack('!4H', data[:8])
    data = data[8:]
    printer("==================UDP Header=================\n")
    printer("Source port: \t" + str(sniff[0]) + '\n')
    printer("Destination port: \t" + str(sniff[1]) + '\n')
    printer("Length: \t" + str(sniff[2]) + '\n')
    printer("Checksum: \t" + str(sniff[3]) + '\n')
    printer("=============================================\n")
    return data


def ipv4(data):
    sniff = struct.unpack('!6H4s4s', data[:20])
    data = data[20:]
    printer("=================IPv4 Header===================\n")
    printer("Version: \t" + str(sniff[0] >> 12) + '\n')
    if ((sniff[0] >> 8) & 0x0f) > 5:
        printer("This Header has Options field attached to it\n")
    else:
        printer("Internet Header Length: \t" + str((sniff[0] >> 8) & 0x0f) + '\n')
    printer("DSCP: \t" + str((sniff[0] >> 2) & 0x003f) + '\n')
    printer("ECN: \t" + str(sniff[0] & 0x0003) + '\n')
    printer("Total length: \t" + str(sniff[1]) + '\n')
    printer("Identification: \t" + str(sniff[2]) + '\n')
    printer("Reserved Flag: \t" + str(sniff[3] >> 15) + '\n')
    printer("Don't Fragment Flag: \t" + str((sniff[3] >> 14) & 0x1) + '\n')
    printer("More Fragments Flag: \t" + str((sniff[3] >> 13) & 0x1) + '\n')
    printer("Fragment Offset: \t" + str(sniff[3] & 0x1fff) + '\n')
    printer("Time To Live: \t" + str(sniff[4] >> 8) + '\n')
    if (sniff[4] & 0x00ff) == 6:
        printer("Protocol: \tTCP " + str(sniff[4] & 0x00ff) + '\n')
    elif (sniff[4] & 0x00ff) == 17:
        printer("Protocol: \tUDP " + str(sniff[4] & 0x00ff) + '\n')
    else:
        printer("Protocol: \t" + str(sniff[4] & 0x00ff) + '\n')
    printer("Header Checksum: \t" + str(sniff[5]) + '\n')
    printer("Source IPv4 Address: \t" + str(socket.inet_ntoa(sniff[6])) + '\n')
    printer("Destination IPv4 Address: \t" + str(socket.inet_ntoa(sniff[7])) + '\n')
    printer("===============================================\n")
    return data, (sniff[4] & 0x00ff)


def arp(data):
    sniff = struct.unpack('!4H6s4s6s4s', data)
    printer("========Address Resolution Protocol===========\n")
    printer("Hardware Type: \t" + str(sniff[0]) + '\n')
    printer("Protocol Type: \t" + str(hex(sniff[1])) + '\n')
    printer("Hardware Size: \t" + str((sniff[2] >> 8)) + '\n')
    printer("Protocol Size: \t" + str(sniff[2] & 0x00ff) + '\n')
    printer("operation: \t" + str(sniff[3]) + '\n')
    printer("Sender MAC Address: \t" + str(binascii.hexlify(sniff[4])) + '\n')
    printer("Sender IPv4 Address: \t" + str(socket.inet_ntoa(sniff[5])) + '\n')
    printer("Target MAC Address: \t" + str(binascii.hexlify(sniff[6])) + '\n')
    printer("Target IPv4 Address: \t" + str(socket.inet_ntoa(sniff[7])) + '\n')
    printer("==============================================\n")
    return


def l2_analyser(data):
    sniff = struct.unpack('!6s6sH', data[:14])
    data = data[14:]
    printer("==========Layer 2 Ethernet Frame===========\n")
    printer("Destination MAC Address: \t" + str(binascii.hexlify(sniff[0])) + '\n')
    printer("Source MAC Address: \t" + str(binascii.hexlify(sniff[1])) + '\n')
    if hex(sniff[2]) == '0x8100':
        printer("This frame has 802.1Q Tag\n")
    elif hex(sniff[2]) == '0x88a8':
        printer("This frame has 802.1ad Tag\n")
    elif hex(sniff[2]) == '0x800':
        printer("Type: \tIPv4 " + str(hex(sniff[2])) + '\n')
    elif hex(sniff[2]) == '0x806':
        printer("Type: \tARP " + str(hex(sniff[2])) + '\n')
    else:
        printer("Type: " + str(hex(sniff[2])) + '\n')
    printer("===========================================\n")
    return data, hex(sniff[2])


def main():
    while True:
        printer("\n\n\n")
        sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x003))
        data, l3_proto = l2_analyser(sock.recv(2048))
        if l3_proto == '0x806':
            arp(data)
        elif l3_proto == '0x800':
            data, l4_proto = ipv4(data)
            if l4_proto == 17:
                data = udp(data)
            elif l4_proto == 6:
                data = tcp(data)
    return


main()
