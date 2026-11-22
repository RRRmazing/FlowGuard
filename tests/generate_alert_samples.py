"""Create deterministic offline-only alert fixtures. Never sends network traffic."""
import struct
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from generate_stage1_samples import checksum

ROOT = Path(__file__).resolve().parent / 'data'
SRC = bytes.fromhex('024c7a91bd36')
DST = bytes.fromhex('028fd267ac10')
CHANGED_MAC = bytes.fromhex('069e43a862f1')
IP4 = [ipaddress.ip_address(x).packed for x in ('192.168.10.23', '192.168.10.80')]
BASE_TIME = int(datetime(2026, 11, 22, 14, 30, tzinfo=timezone(timedelta(hours=8))).timestamp())

def ethernet(kind, payload):
    return DST + SRC + struct.pack('!H', kind) + payload

def write(name, packets):
    data = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for milliseconds, frame in packets:
        seconds, remainder = divmod(milliseconds, 1000)
        data += struct.pack('<IIII', BASE_TIME + seconds, remainder * 1000, len(frame), len(frame)) + frame
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

def echo(request=True, sequence=1):
    payload = bytearray(struct.pack('!BBHHH', 8 if request else 0, 0, 0, 0x4c7a, sequence) + bytes(range(32)))
    payload[2:4] = struct.pack('!H', checksum(payload))
    return ipv4(1, payload, reply=not request)

def arp(mac):
    payload = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) + mac + IP4[0] + DST + IP4[1]
    frame = ethernet(0x0806, payload)
    return (frame[:6] + mac + frame[12:]).ljust(60, b'\0')

def main():
    packets = []
    for i in range(600):
        packets.append((i, tcp(49152+i,443,0x4a7c1200+i*7919,0,2)))
    ports = (21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,2375,3306,3389,5432,5900,6379,8080,8443)
    for i, port in enumerate(ports):
        packets.append((11000+i,tcp(51000+i,port,0x7359a280+i*4096,0,2)))
    for i in range(350):
        packets.append((20000 + i, echo(sequence=i+1)))
    for i in range(1100):
        body=b'FlowGuard offline UDP sample '+struct.pack('!I',i)+bytes(range(64))
        packets.append((30000+i,ipv4(17,struct.pack('!HHHH',52000,8080,8+len(body),0)+body)))
    packets += [(40000, arp(SRC)), (40010, arp(CHANGED_MAC))]
    write('alerts-demo.pcap', packets)
    normal = []
    for i in range(10):
        client, server, port = 0x6f38a421+i*4096, 0xa2d67031+i*8192, 49152+i
        normal.append((i*1000, tcp(port,443,client,0,2)))
        normal.append((i*1000+1, tcp(443,port,server,client+1,0x12,reply=True)))
        normal.append((i*1000+2, tcp(port,443,client+1,server+1,0x10)))
        normal.append((i * 1000 + 3, echo(sequence=i+1)))
        normal.append((i * 1000 + 4, echo(False,sequence=i+1)))
    normal += [(10000, arp(SRC)), (10010, arp(SRC))]
    write('alerts-normal.pcap', normal)
    print(f'Wrote {len(packets)} anomaly and {len(normal)} low-rate baseline packets')

if __name__ == '__main__':
    main()
