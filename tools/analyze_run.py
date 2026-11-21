"""Analyze one FlowGuard GUI run. Never combine restarted processes into a 24h run.

Primary author: Xie Fuxiang. AI-assisted implementation, pending user review.
Standard-library summary; matplotlib is required only for plots.
"""
import argparse
import csv
import json
import math
from pathlib import Path


def value(row, key):
    text = row.get(key, '')
    if text == '':
        return None
    number = float(text)
    return number if math.isfinite(number) else None


def counter(row, key):
    text = row.get(key, '')
    return int(text) if text != '' else None


def summarize(rows, metadata, result, events):
    if not rows:
        raise ValueError('No resource samples: cannot analyze an empty run')
    times = [value(r, 'elapsed_seconds') for r in rows]
    if any(t is None for t in times) or any(b <= a for a, b in zip(times, times[1:])):
        raise ValueError('Sample times must be strictly increasing within one process run')
    intervals = [b - a for a, b in zip(times, times[1:])]
    weighted_cpu = sum((value(rows[i], 'cpu_percent') or 0) * dt
                       for i, dt in enumerate(intervals, 1)
                       if value(rows[i], 'cpu_percent') is not None)
    cpu_seconds = sum(dt for i, dt in enumerate(intervals, 1)
                      if value(rows[i], 'cpu_percent') is not None)
    cpus = [value(r, 'cpu_percent') for r in rows if value(r, 'cpu_percent') is not None]
    memory = [(t, value(r, 'working_set_bytes')) for t, r in zip(times, rows)
              if value(r, 'working_set_bytes') is not None]
    sessions = {}
    session_records = list(rows) + [e['detail']['session'] for e in events
                                   if e.get('event') == 'control_finished' and 'session' in e.get('detail', {})]
    for r in session_records:
        session = str(r['session_id'])
        if session == '0':
            continue
        # Counters are cumulative per session. Do not sum consecutive snapshots.
        current = sessions.setdefault(session, {'source': r['source']})
        for key in ('total_packets', 'total_bytes', 'saved_packets', 'queue_dropped',
                    'driver_dropped', 'interface_dropped', 'display_dropped', 'late_history_packets', 'list_evicted'):
            v = counter(r, key)
            if v is not None:
                current[key] = max(current.get(key, 0), int(v))
    io = {}
    for key in ('process_read_bytes', 'process_write_bytes'):
        valid = [counter(r, key) for r in rows if counter(r, key) is not None]
        io[key + '_delta'] = valid[-1] - valid[0] if len(valid) >= 2 else None
    delays = [value(r, 'gui_delay_ms') for r in rows if value(r, 'gui_delay_ms') is not None]
    error_events = [e for e in events if e.get('event') in ('source_error', 'saving_error') or
                    (e.get('event') == 'control_finished' and not e.get('detail', {}).get('ok', True))]
    elapsed = result.get('duration_seconds') if result else None
    normal = bool(result and result.get('normal_exit'))
    return {
        'run_id': metadata.get('run_id'), 'commit': metadata.get('commit'),
        'dirty_at_configure': metadata.get('dirty_at_configure'),
        'started': metadata.get('started'), 'ended': result.get('ended') if result else None,
        'duration_seconds': elapsed, 'observed_sample_span_seconds': times[-1] - times[0],
        'normal_exit': normal, 'logging_error': result.get('logging_error') if result else 'No result.json; abnormal/incomplete run',
        'damaged_event_records': sum(e.get('event') == 'damaged_event_record' for e in events),
        'samples': len(rows), 'missing_cpu_samples': len(rows) - len(cpus),
        'missing_memory_samples': len(rows) - len(memory),
        'gaps_over_2_5_seconds': sum(dt > 2.5 for dt in intervals),
        'max_sampling_interval_seconds': max(intervals, default=0),
        'cpu_time_weighted_mean_percent': weighted_cpu / cpu_seconds if cpu_seconds else None,
        'cpu_peak_percent': max(cpus, default=None),
        'memory_start_bytes': memory[0][1] if memory else None,
        'memory_end_bytes': memory[-1][1] if memory else None,
        'memory_peak_bytes': max((m for _, m in memory), default=None),
        'memory_change_bytes': memory[-1][1] - memory[0][1] if memory else None,
        'memory_endpoint_growth_bytes_per_hour': ((memory[-1][1] - memory[0][1]) * 3600 /
                                                 (memory[-1][0] - memory[0][0])) if len(memory) > 1 else None,
        'max_queue_packets': max((value(r, 'queued_packets') or 0 for r in rows), default=0),
        'max_gui_timer_delay_ms': max(delays, default=None),
        'sessions': sessions, 'recorded_error_events': error_events, **io,
        'duration_at_least_24h': bool(elapsed is not None and elapsed >= 86400),
        'manual_review_required': True,
        'notes': [
            'Duration is process lifetime; review session/source states to establish actual capture coverage.',
            '24h duration alone is not a passing verdict. Inspect gaps, errors, responsiveness and normal computer use.',
            'Memory endpoint growth is descriptive, not proof of a memory leak.',
            'GUI timer delay is event-loop scheduling delay, not all user interactions latency.',
            'Process I/O is not physical disk throughput. First samples omit earlier process I/O.',
            'Per-session counters also use control-result snapshots; inspect event logs for very short sessions.',
        ],
    }


def plot(rows, output):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(4, 2, figsize=(15, 13), constrained_layout=True)
    keys = [('cpu_percent', 'Process CPU (%)', 1), ('working_set_bytes', 'Working set (MiB)', 1024**2),
            ('process_read_bytes', 'Process reads (KiB/s)', 1024), ('process_write_bytes', 'Process writes (KiB/s)', 1024),
            ('total_packets', 'Processed packets/s', 1), ('queued_packets', 'Capture queue (packets)', 1),
            ('queue_dropped', 'Capture queue drops (per session)', 1), ('gui_delay_ms', 'GUI timer delay (ms)', 1)]
    times = [value(r, 'elapsed_seconds') for r in rows]
    for ax, (key, title, scale) in zip(axes.flat, keys):
        xs, ys = [], []
        for i, row in enumerate(rows):
            t, v = times[i], value(row, key)
            gap = i > 0 and times[i] - times[i-1] > 2.5
            reset = i > 0 and row['session_id'] != rows[i-1]['session_id']
            if gap or (key in ('total_packets', 'queue_dropped') and reset):
                xs.append(t / 3600); ys.append(math.nan)
            if key in ('process_read_bytes', 'process_write_bytes', 'total_packets'):
                previous = value(rows[i-1], key) if i else None
                if i == 0 or previous is None or v is None or (key == 'total_packets' and reset) or gap or v < previous:
                    v = None
                else:
                    v = (v - previous) / (times[i] - times[i-1])
            xs.append(t / 3600); ys.append(v / scale if v is not None else math.nan)
        ax.plot(xs, ys, color='#087f83', linewidth=1)
        ax.set_title(title); ax.set_xlabel('Process elapsed hours'); ax.grid(alpha=.2)
    fig.suptitle('FlowGuard GUI run — actual recorded data', fontsize=16)
    fig.savefig(output / 'performance.png', dpi=150)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_dir', type=Path)
    parser.add_argument('--output', type=Path, required=True, help='New output directory (never overwrites evidence)')
    parser.add_argument('--no-plots', action='store_true', help='Standard-library summary only')
    args = parser.parse_args()
    root = args.run_dir
    with (root / 'resources.csv').open(encoding='utf-8', newline='') as f:
        rows = list(csv.DictReader(f))
    metadata = json.loads((root / 'run.json').read_text(encoding='utf-8'))
    result_path = root / 'result.json'
    result = json.loads(result_path.read_text(encoding='utf-8')) if result_path.exists() else None
    events = []
    event_path = root / 'events.jsonl'
    if event_path.exists():
        for line in event_path.read_text(encoding='utf-8').splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                events.append({'event': 'damaged_event_record', 'line': line})
    summary = summarize(rows, metadata, result, events)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    if not args.no_plots:
        plot(rows, args.output)
    report = '# FlowGuard 连续运行测试分析\n\n'
    report += '本报告来自一个进程运行目录，不合并重启记录。自动汇总不代替人工验收。\n\n'
    report += '| 指标 | 实测结果 |\n| --- | --- |\n'
    for key, val in summary.items():
        if key not in ('notes', 'sessions', 'recorded_error_events'):
            report += f'| {key} | {val if val is not None else "不可用"} |\n'
    if not args.no_plots:
        report += '\n![完整时段性能曲线](performance.png)\n'
    report += '\n## 分会话计数\n\n```json\n' + json.dumps(summary['sessions'], indent=2) + '\n```\n'
    report += '\n## 必须结合原始记录分析\n\n'
    report += '\n'.join('- ' + note for note in summary['notes'])
    report += '\n\n- CPU 是否随流量合理变化？\n- 内存是否趋稳，还是持续增长？\n- I/O、保存文件大小与保存策略是否一致？\n- 队列是否积压，各类丢弃与错误有何原因？\n- 人工操作是否响应，是否影响电脑正常工作？\n'
    report += '\n请补充真实观察、异常与局限；不足 24 小时必须标为短时检查。\n'
    (args.output / 'report.md').write_text(report, encoding='utf-8')
    print(json.dumps({'output': str(args.output), 'samples': len(rows), 'duration_at_least_24h': summary['duration_at_least_24h']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
