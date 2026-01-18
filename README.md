# RIVERSIDE RESEARCH GOATHACKS CHALLENGE

### Discussion Questions

1. A concise system overview (architecture, components, assumptions).
    This is a storage-based covert channel that operates on failed checksums. The problem description highlights the unreliability of the target network in the regime, specifically how packets can be dropped, delayed, or selectively blocked at will. To me, this immediately rules out timing-based covert channels, as they can become fragile in unreliable network conditions. In unreliable network conditions, however, failed checksum checks are commonplace due to bit flips in transit, so deliberately injecting a failed checksum into a UDP packet is the main vector of data transfer in this channel, transferring 16 bits of secret data per frame.

    To promote secrecy, this is a protocol-hopping covert channel, using an RNG to randomly switch between DNS and RTP packets. The actual mechanism of this channel is over UDP, so it is protocol-agnostic for application layer protocols (if we want to in the future, we can add more protocols to provide further variability in the packets being sent). Also, after sending one “bad checksum” packet containing the secret data, the sender will send 1-3 “good checksum” packets to appear normal. The receiver will know to drop these packets.

    I assume the sending machine regularly uses DNS and RTP.
    I assume the receiving machine is capable of disguising itself as a DNS or RTP server.
    I assume the sending and receiving machines have root access, since raw sockets are being used.
    I assume a python interpreter and the scapy python package are both installed on the target machines.

4. A description of the data exfiltration pathway(s).
    The main data exfiltration pathway is through the checksum field on a UDP packet, where a checksum mismatch occurs.

5. An explanation of how data is protected, disguised, and attributed (or not).
    The data itself is not protected, since it exists as raw bytes in the checksum field.
    Data is disguised through common protocols over UDP like DNS and RTP. Protocol hopping and sparse “bad checksum” packets add variability to network traffic.
    Since we’re dealing with raw sockets, the source IP address can be changed on the sender, making it hard to attribute data to the sender’s machine.

6. A discussion of limitations, risks, and possible detection vectors.
    There are many limitations with this channel, as it exists as a proof-of-concept.
    * UDP checksums are optional headers, and may be flagged.
    * Bit flips can occur naturally through unreliable data transfer and cause the receiver to treat that packet’s checksum as data to interpret.
    * The application layer protocols used over UDP are chosen at random (protocol hopping), but the packets themselves are static. This can be remedied with more sample packets to send and another RNG to send different packets at random.
    * Because we send “good packets” after each “bad packet,” throughput is limited. Further work should look for more places in all layers of the network stack to hide data as a part of this covert channel, and randomly hop between them to promote more unstructured data transfer.
    * The receiver may be expected to send back a response packet to appear "normal."