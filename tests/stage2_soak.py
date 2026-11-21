"""Real localhost capture/parse/statistics/save/readback soak; test-only psutil dependency.

Output directory must not exist. Only generated local UDP traffic is saved.
Run with --seconds 3600 for the stage-2 one-hour trial, never the 24-hour final test.
"""
import argparse
import csv
import datetime
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import threading
import time

import psutil


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=3600)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 86400:
        parser.error('seconds must be 1..86400')
    args.output_dir.mkdir(parents=True, exist_ok=False)
    output = args.output_dir.resolve()
    env = os.environ.copy()
    env['PATH'] = str(Path(env.get('SystemRoot', r'C:\Windows')) / 'System32' / 'Npcap') + os.pathsep + env['PATH']
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(('127.0.0.1', 0))
    receiver.setblocking(False)
    port = receiver.getsockname()[1]
    stop = threading.Event()
    sent = [0]

    def traffic():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            while not stop.is_set():
                sender.sendto(b'FlowGuard-stage2-owned-localhost-traffic-' + b'x' * 128, ('127.0.0.1', port))
                sent[0] += 1
                try:
                    while receiver.recvfrom(4096):
                        pass
                except BlockingIOError:
                    pass
                stop.wait(0.1)

    command = [str(args.probe.resolve()), '--device', r'\Device\NPF_Loopback', '--bpf', f'udp and dst port {port}',
               '--seconds', str(args.seconds), '--output', str(output / 'owned-traffic.pcap')]
    start_wall = datetime.datetime.now(datetime.timezone.utc).isoformat()
    start = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                               encoding='utf-8', env=env)
    monitor = psutil.Process(process.pid)
    monitor.cpu_percent()
    producer = threading.Thread(target=traffic)
    producer.start()
    last_report = 0
    final = {}
    samples = []
    try:
        with (output / 'backend.log').open('w', encoding='utf-8') as log, \
                (output / 'resources.csv').open('w', encoding='utf-8', newline='') as resource_log:
            writer = csv.DictWriter(resource_log, fieldnames=['elapsed_seconds', 'rss_bytes', 'cpu_percent',
                                                             'read_bytes', 'write_bytes', 'backend'])
            writer.writeheader()
            for line in process.stdout:
                log.write(line)
                log.flush()
                elapsed = time.monotonic() - start
                values = dict(re.findall(r'\b([a-z_]+)=([0-9.e+\-]+)', line))
                if line.startswith('FINAL '):
                    final = values
                try:
                    memory = monitor.memory_info().rss
                    io = monitor.io_counters()
                    cpu = monitor.cpu_percent() / (psutil.cpu_count() or 1)
                except psutil.NoSuchProcess:
                    continue
                row = dict(elapsed_seconds=round(elapsed, 3), rss_bytes=memory, cpu_percent=cpu,
                           read_bytes=io.read_bytes, write_bytes=io.write_bytes, backend=line.strip())
                writer.writerow(row)
                resource_log.flush()
                samples.append((elapsed, memory))
                if elapsed - last_report >= 60:
                    print(f'soak elapsed={elapsed:.0f}s packets={values.get("packets", "?")} rss={memory} cpu={cpu:.2f}%', flush=True)
                    last_report = elapsed
            code = process.wait(timeout=20)
    finally:
        stop.set()
        producer.join()
        receiver.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
    elapsed = time.monotonic() - start
    live_ok = code == 0 and final.get('error') == '0' and final.get('saving_error') == '0' and int(final.get('saved', 0)) > 0
    imported = subprocess.run([str(args.probe.resolve()), '--input', str(output / 'owned-traffic.pcap'), '--seconds', '60'],
                              capture_output=True, text=True, encoding='utf-8', env=env, timeout=90)
    (output / 'readback.log').write_text(imported.stdout + imported.stderr, encoding='utf-8')
    last = [line for line in imported.stdout.splitlines() if line.startswith('FINAL ')]
    readback = dict(re.findall(r'\b([a-z_]+)=([0-9.e+\-]+)', last[-1])) if last else {}
    consistent = imported.returncode == 0 and readback.get('packets') == final.get('saved')
    result = dict(start_utc=start_wall, end_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  duration_seconds=elapsed, requested_seconds=args.seconds, sent_packets=sent[0],
                  final=final, readback=readback, returncode=code, live_ok=live_ok,
                  readback_consistent=consistent, samples=len(samples),
                  peak_rss_bytes=max((m for _, m in samples), default=0),
                  passed=live_ok and consistent and elapsed >= args.seconds)
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
