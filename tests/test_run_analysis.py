"""Check evidence calculations: irregular intervals, reset counters, missing samples."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('analysis', Path(__file__).parents[1] / 'tools/analyze_run.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AnalysisTests(unittest.TestCase):
    def test_intervals_sessions_and_unknowns(self):
        rows = []
        for t, cpu, memory, session, packets in [(1, '', '100', '1', '5'), (2, '10', '120', '1', '9'), (5, '30', '', '2', '2')]:
            rows.append(dict(elapsed_seconds=str(t), cpu_percent=cpu, working_set_bytes=memory,
                             session_id=session, source='1', total_packets=packets))
        result = module.summarize(rows, {'run_id': 'one'}, {'normal_exit': True, 'duration_seconds': 5}, [])
        self.assertEqual(result['cpu_time_weighted_mean_percent'], 25)
        self.assertEqual(result['missing_cpu_samples'], 1)
        self.assertEqual(result['missing_memory_samples'], 1)
        self.assertEqual(result['gaps_over_2_5_seconds'], 1)
        self.assertEqual(result['sessions']['1']['total_packets'], 9)
        self.assertEqual(result['sessions']['2']['total_packets'], 2)
        self.assertFalse(result['duration_at_least_24h'])
        self.assertTrue(result['manual_review_required'])

    def test_restarted_or_corrupt_time_rejected(self):
        with self.assertRaises(ValueError):
            module.summarize([{'elapsed_seconds': '2'}, {'elapsed_seconds': '1'}], {}, None, [])

    def test_large_counters_and_abnormal_exit(self):
        n = 2**60 + 3
        rows = [dict(elapsed_seconds='1', session_id='1', source='1', total_packets=str(n))]
        result = module.summarize(rows, {}, None, [])
        self.assertEqual(result['sessions']['1']['total_packets'], n)
        self.assertFalse(result['normal_exit'])
        self.assertFalse(result['duration_at_least_24h'])


if __name__ == '__main__':
    unittest.main()
