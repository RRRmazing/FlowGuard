"""Regenerate only the synthetic stage-1 PCAP fixtures; no live traffic or dependencies."""
import ipaddress
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent / 'data'
SRC = bytes.fromhex('020000000001')
DST = bytes.fromhex('020000000002')
IP4 = [ipaddress.ip_address(x).packed for x in ('192.0.2.1', '198.51.100.2')]
IP6 = [ipaddress.ip_address(x).packed for x in ('2001:db8::1', '2001:db8::2')]

def checksum(b):
    if len(b) % 2:
        b += b'\0'
    value = sum(struct.unpack('!' + 'H' * (len(b)//2), b))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535

def transport(protocol, body=b'', flags=2, dns=False):
    if protocol == 17:
        return struct.pack('!HHHH', 53001 if dns else 1234, 53 if dns else 8080, 8+len(body), 0)+body
    return struct.pack('!HHIIBBHHH', 53002 if dns else 2345, 53 if dns else 443, 1, 0, 0x50, flags, 8192, 0, 0)+body

def network(v6, protocol, payload, extension=None, options=False):
    # Valid transport checksums make the samples usable for independent inspection.
    payload = bytearray(payload)
    addr = IP6 if v6 else IP4
    pseudo = b''.join(addr)+(struct.pack('!I3xB', len(payload), protocol) if v6 else struct.pack('!BBH', 0, protocol, len(payload)))
    offset = 6 if protocol == 17 else 16
    payload[offset:offset+2] = struct.pack('!H', checksum(pseudo+payload) or 65535)
    if v6:
        data = (bytes([protocol, 0])+bytes(6) if extension is not None else b'')+payload
        return struct.pack('!IHBB', 6<<28, len(data), protocol if extension is None else extension, 63)+b''.join(addr)+data
    opt = bytes([1,1,0,0]) if options else b''
    header = bytearray(struct.pack('!BBHHHBBH', 0x46 if options else 0x45, 0, 20+len(opt)+len(payload), 123, 0x4000, 64, protocol, 0)+b''.join(addr)+opt)
    header[10:12] = struct.pack('!H', checksum(header))
    return header+payload

def ethernet(kind, payload, tags=0):
    if not tags:
        return DST+SRC+struct.pack('!H',kind)+payload
    tag = struct.pack('!HH', 100, kind) if tags == 1 else struct.pack('!HHHH', 200, 0x8100, 100, kind)
    return DST+SRC+struct.pack('!H', 0x8100 if tags == 1 else 0x88a8)+tag+payload

def pcap(path, packets):
    data = bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    for i, packet in enumerate(packets):
        data += struct.pack('<IIII',1700000000+i,123456,len(packet),len(packet))+packet
    path.write_bytes(data)

def main():
    question = b'\x07example\x03com\0'+struct.pack('!HH',1,1)
    query = struct.pack('!HHHHHH',0x4321,0x0100,1,0,0,0)+question
    response = struct.pack('!HHHHHH',0x4321,0x8180,1,1,0,0)+question+bytes.fromhex('c00c000100010000003c0004')+bytes([192,0,2,9])
    cases=[]
    def add(label, v6=False, proto=17, body=b'', flags=2, dns=False, tags=0, ext=None, options=False):
        segment=transport(proto,body,flags,dns)
        packet=ethernet(0x86dd if v6 else 0x0800,network(v6,proto,segment,ext,options),tags)
        cases.append((label,packet,'Complete'))
    add('IPv4 UDP')
    add('IPv4 TCP SYN',proto=6)
    add('IPv4 TCP FIN ACK',proto=6,flags=0x11)
    add('IPv4 TCP RST ACK',proto=6,flags=0x14)
    add('IPv6 UDP',v6=True)
    add('IPv6 TCP SYN ACK',v6=True,proto=6,flags=0x12)
    for opcode in (1,2):
        arp=struct.pack('!HHBBH',1,0x0800,6,4,opcode)+SRC+IP4[0]+(bytes(6) if opcode==1 else DST)+IP4[1]
        cases.append(('ARP request' if opcode==1 else 'ARP reply',ethernet(0x0806,arp).ljust(60,b'\0'),'Complete'))
    add('UDP DNS query',body=query,dns=True)
    add('UDP DNS compressed answer',body=response,dns=True)
    add('IPv6 UDP DNS',v6=True,body=query,dns=True)
    add('TCP DNS',proto=6,body=struct.pack('!H',len(query))+query,flags=0x18,dns=True)
    add('VLAN IPv4 UDP',tags=1)
    add('QinQ IPv6 UDP',v6=True,tags=2)
    add('IPv6 Hop-by-Hop UDP',v6=True,ext=0)
    add('IPv6 atomic fragment UDP',v6=True,ext=44)
    add('IPv4 options UDP',options=True)
    cases.append(('Non-IP experimental EtherType',ethernet(0x88b5,bytes(46)),'Unsupported'))
    pcap(ROOT/'stage1-protocols.pcap',[x[1] for x in cases])
    (ROOT/'stage1-protocols.json').write_text(json.dumps([{'number':i+1,'name':name,'status':status} for i,(name,_,status) in enumerate(cases)],ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(f'Generated {len(cases)} synthetic protocol samples')

if __name__=='__main__':
    main()
