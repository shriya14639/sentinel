
import unittest

from pipeline.orchestrator import MemoryTrendTracker


class TestMemoryTrendTracker(unittest.TestCase):
    def setUp(self):
        self.tracker = MemoryTrendTracker()

    def make_event(self, memory, system_id="server-1"):
        return {
            "system_id": system_id,
            "metrics": {"memory_pct": memory},
        }

    def test_no_trend_before_four_readings(self):
        self.assertFalse(self.tracker.check(self.make_event(60)))
        self.assertFalse(self.tracker.check(self.make_event(65)))
        self.assertFalse(self.tracker.check(self.make_event(70)))

    def test_detects_steady_memory_increase(self):
        readings = [60, 64, 68, 72]
        results = [
            self.tracker.check(self.make_event(value))
            for value in readings
        ]

        self.assertEqual(results, [False, False, False, True])

    def test_does_not_detect_small_increase(self):
        readings = [60, 62, 64, 66]
        results = [
            self.tracker.check(self.make_event(value))
            for value in readings
        ]

        self.assertFalse(results[-1])

    def test_does_not_detect_decreasing_memory(self):
        readings = [80, 75, 70, 65]
        results = [
            self.tracker.check(self.make_event(value))
            for value in readings
        ]

        self.assertFalse(results[-1])

    def test_tracks_each_system_separately(self):
        for value in [60, 64, 68]:
            self.tracker.check(self.make_event(value, "server-1"))

        for value in [60, 64, 68]:
            self.tracker.check(self.make_event(value, "server-2"))

        self.assertTrue(
            self.tracker.check(self.make_event(72, "server-1"))
        )
        self.assertTrue(
            self.tracker.check(self.make_event(72, "server-2"))
        )


if __name__ == "__main__":
    unittest.main()
