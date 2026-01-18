import sys

from scapy.all import *
conf.verb = 0

#----------------------------------------------------------------------------------------------------#
# GLOBALS
#----------------------------------------------------------------------------------------------------#

# MODE VALUES
DNS_MODE = 1
RTP_MODE = 2

# CONNECTION SETTINGS
HOST = "127.0.0.1"
PORT = 1337
SOURCE_IP = "127.0.0.1"

#----------------------------------------------------------------------------------------------------#
# FUNCTIONS
#----------------------------------------------------------------------------------------------------#

def covert_send(send_bytes):
    
    # decide whether or not we're sending DNS or QUIC
    SELECTED_MODE = random.randint(1,2)

    # build the packet
    if(SELECTED_MODE == RTP_MODE):
        good_packet = IP(src=SOURCE_IP, dst=HOST) / UDP(dport=PORT) / RTP(payload_type=96, sequence=1, timestamp=123456, sourcesync=0x11223344) / Raw(b"\x00" * 160)
    elif(SELECTED_MODE == DNS_MODE):
        good_packet = IP(dst=HOST) / UDP(dport=PORT) / DNS(rd=1, qd=DNSQR(qname="danieljreynolds.com", qtype="A"))
    else:
        print("[SENDER]: Unsupported protocol")
    bad_packet = good_packet.copy()
    bad_packet[UDP].chksum = send_bytes

    # send the packet
    send(bad_packet)
    ms = random.randint(1, 20)
    time.sleep(ms / 1000.0)

    # send 1-3 good packets
    num_good_packets = random.randint(1,3)
    for i in range(num_good_packets):
        send(good_packet)
        ms = random.randint(1, 20)
        time.sleep(ms / 1000.0)

#----------------------------------------------------------------------------------------------------#
# SENDER START
#----------------------------------------------------------------------------------------------------#

# open the file with secret data
mode = sys.argv[1]
if(mode == "text"):
    secret_file = open("beemovie.txt")
    secret_data = secret_file.read().encode('utf-8')
elif(mode == "png"):
    secret_file = open("smiley.png", "rb")
    secret_data = secret_file.read()
else:
    print("[SENDER]: mode unsupported")
    exit

# main loop for client to send data
total_bytes = len(secret_data)
sent_bytes = 0
while(sent_bytes + 1 < total_bytes):
    
    # get the next two bytes to send in the next checksum
    current_bad_checksum = secret_data[sent_bytes + 1] | ((secret_data[sent_bytes] << 8) & 0xFF00)

    # send sus packet (bad checksum followed by good)
    covert_send(current_bad_checksum)
    sent_bytes += 2
    print(f"[SENDER]: sent {sent_bytes}/{total_bytes} bytes")
print(f"[SENDER]: done!")