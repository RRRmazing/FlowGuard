"""Compare real parser output with installed Wireshark/TShark, without capturing traffic."""
import argparse
import csv
import io
import ipaddress
import json
import subprocess
from decimal import Decimal
from pathlib import Path

FIELDS = ['frame.number','frame.len','frame.cap_len','frame.time_epoch','eth.src','eth.dst','eth.type','vlan.etype',
          'ip.version','ipv6.version','ip.src','ip.dst','ipv6.src','ipv6.dst','ip.ttl','ipv6.hlim','ip.proto',
          'tcp.srcport','tcp.dstport','tcp.flags','udp.srcport','udp.dstport','arp.src.proto_ipv4','arp.dst.proto_ipv4',
          'arp.opcode','arp.src.hw_mac','arp.dst.hw_mac','dns.id','dns.flags','dns.count.queries','dns.count.answers',
          'dns.qry.name','dns.qry.type','dns.qry.class']

def run(args):
    return subprocess.run(args,check=True,capture_output=True,encoding='utf-8',errors='strict').stdout

def flatten(fields):
    values={}
    for field in fields:
        values[field['name']]=field['value']
        values.update(flatten(field['children']))
    return values

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--probe',required=True)
    p.add_argument('--tshark',required=True)
    p.add_argument('--pcap',required=True)
    p.add_argument('--manifest')
    a=p.parse_args()
    ours=[json.loads(line) for line in run([a.probe,'--json',a.pcap]).splitlines()]
    cmd=[a.tshark,'-n','-r',a.pcap,'-T','fields','-E','separator=/t','-E','occurrence=f']
    for f in FIELDS: cmd+=['-e',f]
    references=[dict(zip(FIELDS,row)) for row in csv.reader(io.StringIO(run(cmd)),delimiter='\t')]
    if not ours or len(ours)!=len(references): raise AssertionError('empty input or different packet counts')
    manifest=json.loads(Path(a.manifest).read_text(encoding='utf-8')) if a.manifest else None
    if manifest and len(manifest)!=len(ours): raise AssertionError('manifest count mismatch')
    checks=0
    for i,(record,ref) in enumerate(zip(ours,references)):
        def same(key,want):
            nonlocal checks
            checks+=1
            if record[key]!=want: raise AssertionError(f'packet {i+1} {key}: FlowGuard={record[key]!r}; Wireshark={want!r}')
        def tree_same(key,want):
            nonlocal checks
            checks+=1
            got=values.get(key)
            if got!=want: raise AssertionError(f'packet {i+1} tree {key}: {got!r} != {want!r}')
        values=flatten(record['fields'])
        same('sequence',int(ref['frame.number']))
        same('originalLength',int(ref['frame.len']))
        same('capturedLength',int(ref['frame.cap_len']))
        same('timestamp_ns',int(Decimal(ref['frame.time_epoch'])*10**9))
        same('sourceMac',ref['eth.src']); same('destinationMac',ref['eth.dst'])
        # Wireshark's first vlan.etype may be the inner VLAN TPID; select final type from decoded IP.
        ether=0x86dd if ref['ipv6.version'] else 0x0800 if ref['ip.version'] else int(ref['eth.type'],16)
        same('etherType',ether)
        source=ref['ip.src'] or ref['ipv6.src'] or ref['arp.src.proto_ipv4']
        dest=ref['ip.dst'] or ref['ipv6.dst'] or ref['arp.dst.proto_ipv4']
        same('sourceIp',str(ipaddress.ip_address(source)) if source else '')
        same('destinationIp',str(ipaddress.ip_address(dest)) if dest else '')
        if ref['ip.version'] or ref['ipv6.version']:
            same('ipVersion',int(ref['ip.version'] or ref['ipv6.version']))
            same('ttlOrHopLimit',int(ref['ip.ttl'] or ref['ipv6.hlim']))
        if ref['tcp.srcport'] or ref['udp.srcport']:
            tcp=bool(ref['tcp.srcport'])
            same('ipProtocol',6 if tcp else 17)
            same('sourcePort',int(ref['tcp.srcport'] or ref['udp.srcport']))
            same('destinationPort',int(ref['tcp.dstport'] or ref['udp.dstport']))
            if tcp: same('tcpFlags',int(ref['tcp.flags'],16)&255)
        if ref['arp.opcode']:
            tree_same('Opcode',ref['arp.opcode']); tree_same('Sender MAC',ref['arp.src.hw_mac']); tree_same('Target MAC',ref['arp.dst.hw_mac'])
        same('isDns',bool(ref['dns.id']))
        if ref['dns.id']:
            for tree,key in [('Transaction ID','dns.id'),('Flags','dns.flags'),('Questions','dns.count.queries'),('Answers','dns.count.answers'),('Question type','dns.qry.type'),('Question class','dns.qry.class')]:
                v=ref[key]; tree_same(tree,str(int(v,16) if v.startswith('0x') else int(v)))
            tree_same('Question name',ref['dns.qry.name'])
        same('status',manifest[i]['status'] if manifest else 'Complete')
        print(f"PASS packet {i+1}: {manifest[i]['name'] if manifest else 'real Ethernet capture'}")
    print(f'PASS: {len(ours)} packets, {checks} field comparisons against Wireshark/TShark')

if __name__=='__main__': main()
