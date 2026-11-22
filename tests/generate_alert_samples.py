"""Create deterministic offline-only alert fixtures. Never sends network traffic."""
import struct
from pathlib import Path
from generate_stage1_samples import checksum, ethernet, network, transport, SRC, DST, IP4

ROOT = Path(__file__).resolve().parent / 'data'

def write(name, packets):
    data = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for milliseconds, frame in packets:
        seconds, remainder = divmod(milliseconds, 1000)
        data += struct.pack('<IIII', 1700000000 + seconds, remainder * 1000, len(frame), len(frame)) + frame
    (ROOT / name).write_bytes(data)

def ipv4(protocol, payload, reply=False):
    addresses = IP4[::-1] if reply else IP4
    payload = bytearray(payload)
    if protocol in (6, 17):
        offset = 16 if protocol == 6 else 6
        payload[offset:offset+2] = b'\0\0'
        pseudo = b''.join(addresses) + struct.pack('!BBH', 0, protocol, len(payload))
        payload[offset:offset+2] = struct.pack('!H', checksum(pseudo + payload) or 65535)
    header = bytearray(struct.pack('!BBHHHBBH', 0x45, 0, 20+len(payload), 1, 0, 64, protocol, 0) + b''.join(addresses))
    header[10:12] = struct.pack('!H', checksum(header))
    frame = ethernet(0x0800, header + payload)
    return frame[6:12] + frame[:6] + frame[12:] if reply else frame

def tcp(source, destination, sequence, acknowledgment, flags, reply=False):
    payload = struct.pack('!HHIIBBHHH', source, destination, sequence, acknowledgment, 0x50, flags, 8192, 0, 0)
    return ipv4(6, payload, reply)

def echo(request=True):
    payload = bytearray(struct.pack('!BBHHH', 8 if request else 0, 0, 0, 1, 1))
    payload[2:4] = struct.pack('!H', checksum(payload))
    return ipv4(1, payload, reply=not request)

def arp(mac):
    payload = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) + mac + IP4[0] + DST + IP4[1]
    frame = ethernet(0x0806, payload)
    return (frame[:6] + mac + frame[12:]).ljust(60, b'\0')

def main():
    packets = []
    for i in range(600):
        packets.append((i, tcp(2345+i,443,1000+i,0,2)))
    for i in range(30):
        segment = bytearray(transport(6))
        segment[2:4] = struct.pack('!H', 1000 + i)
        packets.append((11000 + i, ethernet(0x0800, network(False, 6, segment))))
    for i in range(350):
        packets.append((20000 + i, echo()))
    for i in range(1100):
        packets.append((30000 + i, ethernet(0x0800, network(False, 17, transport(17)))))
    packets += [(40000, arp(SRC)), (40010, arp(bytes.fromhex('020000000099')))]
    write('alerts-demo.pcap', packets)
    normal = []
    for i in range(10):
        client, server, port = 1000+i*10, 5000+i*10, 2345+i
        normal.append((i*1000, tcp(port,443,client,0,2)))
        normal.append((i*1000+1, tcp(443,port,server,client+1,0x12,reply=True)))
        normal.append((i*1000+2, tcp(port,443,client+1,server+1,0x10)))
        normal.append((i * 1000 + 3, echo()))
        normal.append((i * 1000 + 4, echo(False)))
    normal += [(10000, arp(SRC)), (10010, arp(SRC))]
    write('alerts-normal.pcap', normal)
    print(f'Wrote {len(packets)} anomaly and {len(normal)} low-rate baseline packets')

if __name__ == '__main__':
    main()
