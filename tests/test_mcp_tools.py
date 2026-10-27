import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from xml.etree import ElementTree as ET

import networkx as nx

from tests.test_search import Function, View


class ToolError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def load_adapter():
    root = Path(__file__).resolve().parents[1]
    package_name = "callgraph_adapter_test"
    package = types.ModuleType(package_name)
    package.__path__ = [str(root)]

    search_spec = importlib.util.spec_from_file_location(
        f"{package_name}.search", root / "search.py"
    )
    search = importlib.util.module_from_spec(search_spec)
    sys.modules[f"{package_name}.search"] = search
    search_spec.loader.exec_module(search)

    def build_path_graph(paths):
        graph = nx.DiGraph()
        for path in paths:
            graph.add_nodes_from(path)
            graph.add_edges_from(zip(path, path[1:]))
        return graph

    def find_root_paths(view, sink, limits, is_cancelled):
        return search.find_paths_from_roots(view, sink, (1, 2), limits, is_cancelled)

    package.build_path_graph = build_path_graph
    package.find_root_paths = find_root_paths
    package.render_flowgraph = Mock()

    registry = {}
    mcp = types.ModuleType("binaryninja.mcp")
    mcp.ToolCall = object
    mcp.Address = int
    mcp.ToolError = ToolError
    mcp.Minimum = mcp.Maximum = lambda value: value

    def tool(**annotations):
        def decorate(function):
            registry[function.__name__] = (function, annotations)
            return function

        return decorate

    mcp.tool = tool
    binaryninja = types.ModuleType("binaryninja")
    binaryninja.Settings = Mock(
        return_value=types.SimpleNamespace(get_integer=lambda _key: 1_000)
    )
    binaryninja.core_ui_enabled = lambda: True
    binaryninja.mcp = mcp

    modules = {
        package_name: package,
        f"{package_name}.search": search,
        "binaryninja": binaryninja,
        "binaryninja.mcp": mcp,
    }
    spec = importlib.util.spec_from_file_location(
        f"{package_name}.mcp_tools", root / "mcp_tools.py"
    )
    adapter = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(adapter)
        adapter.register_tools()
    return adapter, registry, package


class AdapterTest(unittest.TestCase):
    def setUp(self):
        self.adapter, self.registry, self.package = load_adapter()
        self.source = Function("source", 0x1000)
        self.middle = Function("middle", 0x2000)
        self.target = Function("target<&", 0x3000)
        self.source.calls(self.middle)
        self.middle.calls(self.target)
        self.functions = [self.source, self.middle, self.target]
        self.view = View(entry_functions=[self.source])
        self.view.get_function_at = lambda address: next(
            (function for function in self.functions if function.start == address), None
        )
        self.view.get_functions_containing = lambda address: [
            function
            for function in self.functions
            if function.start <= address < function.start + 16
        ]
        self.call = types.SimpleNamespace(binary_view=self.view, is_cancelled=False)

    def invoke(self, suffix, **arguments):
        return self.registry[f"callgraph_{suffix}"][0](self.call, **arguments)

    def test_six_tools_register_with_expected_annotations(self):
        self.assertEqual(len(self.registry), 6)
        for name, (_, annotations) in self.registry.items():
            self.assertEqual(annotations.get("read_only", False), "draw" not in name)

    def test_find_and_graphml_include_limits_and_stats(self):
        arguments = {
            "source": 0x1000,
            "target": 0x3000,
            "max_paths": 100,
            "max_depth": 50,
            "max_states": 5_000,
            "max_edges": 20_000,
            "max_references_per_function": 500,
        }
        result = self.invoke("find_paths", **arguments)
        self.assertEqual(result["path_count"], 1)
        self.assertFalse(result["truncated"])
        self.assertEqual(result["limits"]["max_edges"], 20_000)
        self.assertGreater(result["search"]["states_expanded"], 0)

        result = self.invoke("export_graphml", **arguments)
        root = ET.fromstring(result["graphml"])
        namespace = {"g": "http://graphml.graphdrawing.org/xmlns"}
        self.assertEqual(len(root.findall("g:graph/g:node", namespace)), 3)
        self.assertIn("target&lt;&amp;", result["graphml"])

    def test_root_results_report_truncation(self):
        result = self.invoke(
            "find_root_paths",
            target=0x3000,
            max_paths=100,
            max_depth=0,
            max_states=5_000,
            max_edges=20_000,
            max_references_per_function=500,
        )
        self.assertTrue(result["truncated"])
        self.assertIn("max_depth", result["truncation_reasons"])

    def test_function_errors(self):
        with self.assertRaises(ToolError) as caught:
            self.invoke(
                "find_paths",
                source=0x9999,
                target=0x3000,
                max_paths=100,
                max_depth=50,
                max_states=5_000,
                max_edges=20_000,
                max_references_per_function=500,
            )
        self.assertEqual(caught.exception.code, "function_not_found")


if __name__ == "__main__":
    unittest.main()
