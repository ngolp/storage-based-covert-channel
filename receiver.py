import socket
import sys

from scapy.all import *
conf.verb = 0

#----------------------------------------------------------------------------------------------------#
# GLOBALS
#----------------------------------------------------------------------------------------------------#

global in_bytes

#----------------------------------------------------------------------------------------------------#
# FUNCTIONS
#----------------------------------------------------------------------------------------------------#

# gets header values for a UDP frame
def parse_ipv4_udp(frame: bytes):
    # get offsets
    l2off = 14
    v_ihl = frame[l2off]
    ver = v_ihl >> 4
    ihl = (v_ihl & 0x0F) * 4

    # verify UDP
    if ver != 4 or ihl < 20 or len(frame) < l2off + ihl:
        return None
    if frame[l2off + 9] != 17:
        return None

    # extract source and dest ips
    src_ip = socket.inet_ntoa(frame[l2off + 12:l2off + 16])
    dst_ip = socket.inet_ntoa(frame[l2off + 16:l2off + 20])

    udpoff = l2off + ihl
    if len(frame) < udpoff + 8:
        return None

    sport, dport, ulen, recv_csum = struct.unpack("!HHHH", frame[udpoff:udpoff + 8])
    if ulen < 8 or len(frame) < udpoff + ulen:
        return None

    # get payload and checksum
    udp_bytes = frame[udpoff:udpoff + ulen]
    csum_bytes = udp_bytes[6:8]

    return {
        "src_ip": src_ip, "dst_ip": dst_ip,
        "sport": sport, "dport": dport,
        "ulen": ulen,
        "recv_csum": recv_csum,
        "udp_bytes": udp_bytes,
        "csum_bytes": csum_bytes,
    }

# one's complement
def ones_complement_sum16(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return s

# calculates a udp checksum
def udp_checksum_ipv4(src_ip: str, dst_ip: str, udp_bytes_with_zero_csum: bytes) -> int:
    pseudo = (
        socket.inet_aton(src_ip) +
        socket.inet_aton(dst_ip) +
        b"\x00" + b"\x11" +
        struct.pack("!H", len(udp_bytes_with_zero_csum))
    )
    s = ones_complement_sum16(pseudo + udp_bytes_with_zero_csum)
    csum = (~s) & 0xFFFF
    return 0xFFFF if csum == 0 else csum

# checks to see if the udp packet has a valid checksum
def is_udp_checksum_valid_ipv4(info) -> bool:
    recv = info["recv_csum"]

    udp_bytes = info["udp_bytes"]
    udp_zero = udp_bytes[:6] + b"\x00\x00" + udp_bytes[8:]
    calc = udp_checksum_ipv4(info["src_ip"], info["dst_ip"], udp_zero)
    return calc == recv

# processes an incoming frame
def process_frame(frame):
    udp_info = parse_ipv4_udp(frame)

    if udp_info is None:
        return
    
    # only accept bad checksum packets as valid to interpret
    if is_udp_checksum_valid_ipv4(udp_info):
        return

    in_bytes = udp_info["csum_bytes"]

    mode = sys.argv[1]
    if(mode == "text"):
        print(bytes(bytearray(in_bytes)).decode("utf-8", errors="replace"), end='', flush=True) # python fuckery
    elif(mode == "png"):
        with open("received.png", "ab") as f:
            f.write(in_bytes)
    else:
        with open("received.bin", "ab") as f:
            f.write(in_bytes)

#----------------------------------------------------------------------------------------------------#
# SERVER START
#----------------------------------------------------------------------------------------------------#

# establish socketed connection
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)) as s:
    while True:

        # get packet and handle it
        frame, addr = s.recvfrom(65535)
        pkttype = addr[2]
        if pkttype != PACKET_OUTGOING:   # or != PACKET_HOST
            continue
        process_frame(frame)

        # once connection finished (and message received), clear the buffer to receive the next message
        in_bytes = []
        in_bytes.append(0)
