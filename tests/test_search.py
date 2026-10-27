import types
import unittest
from dataclasses import dataclass, field

from search import SearchLimits, find_paths_between, find_paths_from_roots


@dataclass(eq=False)
class Function:
    name: str
    start: int
    binding: int = 0
    callees: list = field(default_factory=list)
    callers: list = field(default_factory=list)

    @property
    def symbol(self):
        return types.SimpleNamespace(binding=self.binding)

    def calls(self, callee):
        self.callees.append(callee)
        callee.callers.append(self)


class View:
    def __init__(self, entry_functions=(), code_refs=None, data_refs=None):
        self.entry_functions = list(entry_functions)
        self.code_refs = code_refs or {}
        self.data_refs = data_refs or {}

    def get_code_refs(self, address):
        return iter(self.code_refs.get(address, ()))

    def get_data_refs(self, address):
        return iter(self.data_refs.get(address, ()))

    def get_functions_containing(self, _address):
        return []


class SearchTest(unittest.TestCase):
    def setUp(self):
        self.entry = Function("entry", 0x1000)
        self.left = Function("left", 0x2000)
        self.right = Function("right", 0x3000)
        self.sink = Function("sink", 0x4000)
        self.entry.calls(self.left)
        self.entry.calls(self.right)
        self.left.calls(self.sink)
        self.right.calls(self.sink)
        self.limits = SearchLimits(
            max_paths=100,
            max_depth=20,
            max_states=100,
            max_edges=100,
            max_references_per_function=100,
        )

    def test_converging_paths_and_cycle(self):
        self.right.calls(self.entry)
        result = find_paths_between(self.entry, self.sink, set(), self.limits)
        self.assertEqual(len(result.paths), 2)
        self.assertFalse(result.stats.truncated)
        self.assertEqual(
            {tuple(function.start for function in path) for path in result.paths},
            {(0x1000, 0x2000, 0x4000), (0x1000, 0x3000, 0x4000)},
        )

    def test_path_and_reference_limits_are_reported(self):
        result = find_paths_between(
            self.entry,
            self.sink,
            set(),
            SearchLimits(1, 20, 100, 100, 1),
        )
        self.assertEqual(len(result.paths), 1)
        self.assertEqual(
            result.stats.truncation_reasons,
            {"max_references_per_function"},
        )

        result = find_paths_between(
            self.entry,
            self.sink,
            set(),
            SearchLimits(1, 20, 100, 100, 100),
        )
        self.assertEqual(len(result.paths), 1)
        self.assertIn("max_paths", result.stats.truncation_reasons)

    def test_work_limits_stop_dense_search(self):
        result = find_paths_between(
            self.entry,
            self.sink,
            set(),
            SearchLimits(100, 20, 1, 100, 100),
        )
        self.assertEqual(result.paths, [])
        self.assertIn("max_states", result.stats.truncation_reasons)

        result = find_paths_between(
            self.entry,
            self.sink,
            set(),
            SearchLimits(100, 20, 100, 1, 100),
        )
        self.assertEqual(result.paths, [])
        self.assertIn("max_edges", result.stats.truncation_reasons)

    def test_root_paths_and_high_fan_in_are_bounded(self):
        callers = [Function(f"caller_{index}", 0x5000 + index) for index in range(2_000)]
        for caller in callers:
            caller.calls(self.sink)
        view = View(entry_functions=callers)
        result = find_paths_from_roots(
            view,
            self.sink,
            (1, 2),
            SearchLimits(10, 20, 100, 100, 25),
        )
        self.assertLessEqual(len(result.paths), 10)
        self.assertIn("max_references_per_function", result.stats.truncation_reasons)
        self.assertIn("max_paths", result.stats.truncation_reasons)
        self.assertLessEqual(result.stats.states_expanded, 100)
        self.assertLessEqual(result.stats.edges_examined, 100)

    def test_duplicate_caller_references_cannot_bypass_fan_in_limit(self):
        consumed = 0

        class HighFanInFunction(Function):
            @property
            def caller_sites(inner_self):
                nonlocal consumed
                for index in range(2_000):
                    consumed += 1
                    yield types.SimpleNamespace(
                        address=0x8000 + index,
                        function=self.entry,
                    )

        sink = HighFanInFunction("memcpy", 0x7000)
        result = find_paths_from_roots(
            View(entry_functions=[self.entry]),
            sink,
            (1, 2),
            SearchLimits(100, 20, 100, 100, 25),
        )
        self.assertEqual(consumed, 26)
        self.assertIn("max_references_per_function", result.stats.truncation_reasons)

    def test_dead_end_subtree_does_not_exhaust_budget(self):
        source = Function("source", 0x10000)
        decoy = Function("decoy", 0x11000)
        source.calls(decoy)
        previous = decoy
        for index in range(50):
            function = Function(f"decoy_{index}", 0x12000 + index)
            previous.calls(function)
            previous = function
        middle = Function("middle", 0x13000)
        source.calls(middle)
        middle.calls(self.sink)
        result = find_paths_between(
            source, self.sink, set(), SearchLimits(100, 20, 10, 100, 100)
        )
        self.assertEqual(result.paths, [[source, middle, self.sink]])
        self.assertFalse(result.stats.truncated)

    def test_depth_pruning_reports_truncation(self):
        result = find_paths_between(
            self.entry, self.sink, set(), SearchLimits(100, 1, 100, 100, 100)
        )
        self.assertEqual(result.paths, [])
        self.assertIn("max_depth", result.stats.truncation_reasons)

    def test_callback_reference_edges_are_reported(self):
        registrar = Function("registrar", 0x6000)
        self.entry.calls(registrar)
        callback = Function("callback", 0x7000)
        callback.calls(self.sink)
        view = View(
            entry_functions=[self.entry],
            code_refs={
                callback.start: [types.SimpleNamespace(address=0x6010, function=registrar)]
            },
        )
        result = find_paths_from_roots(view, self.sink, (1, 2), self.limits)
        self.assertEqual(result.reference_edges, {(0x6000, 0x7000)})
        self.assertIn(
            ("ENTRY", [self.entry, registrar, callback, self.sink]),
            result.paths,
        )

    def test_root_depth_boundary_is_explicit(self):
        view = View(entry_functions=[self.entry])
        result = find_paths_from_roots(
            view,
            self.sink,
            (1, 2),
            SearchLimits(100, 0, 100, 100, 100),
        )
        self.assertEqual(result.paths[0][0], "MAX_DEPTH")
        self.assertIn("max_depth", result.stats.truncation_reasons)


if __name__ == "__main__":
    unittest.main()
