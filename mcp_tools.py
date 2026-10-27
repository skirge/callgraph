"""Call graph operations for Binary Ninja's native MCP server."""

from typing import Annotated

from binaryninja import Settings, core_ui_enabled, mcp
import networkx as nx

from . import build_path_graph, find_root_paths, root_starts, show_tree
from .search import SearchCancelled, SearchLimits, find_paths_between


MAX_PATHS = 1_000
MAX_DEPTH = 1_000
MAX_STATES = 100_000
MAX_EDGES = 500_000
MAX_REFERENCES_PER_FUNCTION = 10_000

PositivePaths = Annotated[int, mcp.Minimum(1), mcp.Maximum(MAX_PATHS)]
NonNegativeDepth = Annotated[int, mcp.Minimum(0), mcp.Maximum(MAX_DEPTH)]
PositiveStates = Annotated[int, mcp.Minimum(1), mcp.Maximum(MAX_STATES)]
PositiveEdges = Annotated[int, mcp.Minimum(1), mcp.Maximum(MAX_EDGES)]
PositiveReferences = Annotated[
    int, mcp.Minimum(1), mcp.Maximum(MAX_REFERENCES_PER_FUNCTION)
]


def resolve_function(bv, address):
    function = bv.get_function_at(address)
    if function is None:
        functions = bv.get_functions_containing(address)
        if len(functions) > 1:
            raise mcp.ToolError("ambiguous_function", "Use an exact function start address.")
        function = functions[0] if functions else None
    if function is None:
        raise mcp.ToolError("function_not_found", f"No function at or containing {address:#x}.")
    return function


def require_view(call):
    bv = call.binary_view
    if bv is None:
        raise mcp.ToolError("no_active_binary_view", "Select a BinaryView first.")
    return bv


def function_info(function):
    return {"name": function.name, "address": hex(function.start)}


def _limits(max_paths, max_depth, max_states, max_edges, max_references_per_function):
    return SearchLimits(
        max_paths=max_paths,
        max_depth=max_depth,
        max_states=max_states,
        max_edges=max_edges,
        max_references_per_function=max_references_per_function,
    )


def _stats(stats, limits):
    return {
        "truncated": stats.truncated,
        "truncation_reasons": sorted(stats.truncation_reasons),
        "search": {
            "states_expanded": stats.states_expanded,
            "edges_examined": stats.edges_examined,
            "unique_functions_seen": len(stats.unique_functions),
        },
        "limits": {
            "max_paths": limits.max_paths,
            "max_depth": limits.max_depth,
            "max_states": limits.max_states,
            "max_edges": limits.max_edges,
            "max_references_per_function": limits.max_references_per_function,
        },
    }


def between_paths(
    call,
    source,
    target,
    blacklisted,
    max_paths,
    max_depth,
    max_states,
    max_edges,
    max_references_per_function,
):
    bv = require_view(call)
    start = resolve_function(bv, source)
    end = resolve_function(bv, target)
    limits = _limits(
        max_paths, max_depth, max_states, max_edges, max_references_per_function
    )
    try:
        outcome = find_paths_between(
            start,
            end,
            set(blacklisted or ()),
            limits,
            lambda: call.is_cancelled,
        )
    except SearchCancelled as exc:
        raise mcp.ToolError("cancelled", "Call graph search was cancelled.") from exc
    result = {
        "source": function_info(start),
        "target": function_info(end),
        "paths": [
            [function_info(function) for function in path] for path in outcome.paths
        ],
        "path_count": len(outcome.paths),
        **_stats(outcome.stats, limits),
    }
    tree = ([(start, None)], end, f"{start.name} -> {end.name}")
    return bv, build_path_graph(outcome.paths), result, tree


def root_paths(
    call,
    target,
    max_paths,
    max_depth,
    max_states,
    max_edges,
    max_references_per_function,
):
    bv = require_view(call)
    sink = resolve_function(bv, target)
    limits = _limits(
        max_paths, max_depth, max_states, max_edges, max_references_per_function
    )
    try:
        outcome = find_root_paths(bv, sink, limits, lambda: call.is_cancelled)
    except SearchCancelled as exc:
        raise mcp.ToolError("cancelled", "Call graph search was cancelled.") from exc
    result = {
        "target": function_info(sink),
        "max_depth": limits.max_depth,
        "paths": [
            {
                "root_kind": root_kind,
                "functions": [function_info(function) for function in path],
            }
            for root_kind, path in outcome.paths
        ],
        "path_count": len(outcome.paths),
        **_stats(outcome.stats, limits),
    }
    tree = (root_starts(outcome.paths), sink, f"Discovered roots -> {sink.name}")
    return bv, build_path_graph(
        (path for _, path in outcome.paths), outcome.reference_edges
    ), result, tree


def _check_drawable(graph):
    if not core_ui_enabled():
        raise mcp.ToolError("ui_required", "Drawing call paths requires the Binary Ninja UI.")
    limit = Settings().get_integer("callgraph.limit")
    if graph.number_of_nodes() > limit:
        raise mcp.ToolError("graph_too_large", f"Graph exceeds the configured {limit} node limit.")


def draw_result(bv, graph, result, tree):
    _check_drawable(graph)
    if graph.number_of_nodes() == 0:
        return {**result, "drawn": False}
    starts, target, title = tree
    if not show_tree(bv, graph, starts, target, title):
        raise mcp.ToolError("sidebar_unavailable", "Could not show the Callgraph sidebar.")
    return {**result, "drawn": True}


def graphml_result(graph, result):
    serializable = nx.DiGraph()
    serializable.add_nodes_from(
        (hex(function.start), {"name": function.name, "address": hex(function.start)})
        for function in graph.nodes
    )
    serializable.add_edges_from(
        (hex(source.start), hex(target.start), {"reference": reference})
        for source, target, reference in graph.edges(data="reference", default=False)
    )
    return {**result, "graphml": "\n".join(nx.generate_graphml(serializable))}


def register_tools():
    @mcp.tool(read_only=True, idempotent=True)
    def callgraph_find_paths(
        call: mcp.ToolCall,
        source: mcp.Address,
        target: mcp.Address,
        blacklisted: list[str] | None = None,
        max_paths: PositivePaths = 100,
        max_depth: NonNegativeDepth = 50,
        max_states: PositiveStates = 5_000,
        max_edges: PositiveEdges = 20_000,
        max_references_per_function: PositiveReferences = 500,
    ) -> dict:
        """Find bounded simple call paths between two functions.

        :param source: Source function address, symbol, or address inside a function.
        :param target: Target function address, symbol, or address inside a function.
        :param blacklisted: Exact callee names to exclude while traversing.
        :param max_paths: Maximum paths returned.
        :param max_depth: Maximum callee edges in one path.
        :param max_states: Maximum traversal states expanded.
        :param max_edges: Maximum callee edges examined across the search.
        :param max_references_per_function: Maximum callees followed from one function.
        """
        return between_paths(
            call,
            source,
            target,
            blacklisted,
            max_paths,
            max_depth,
            max_states,
            max_edges,
            max_references_per_function,
        )[2]

    @mcp.tool(read_only=True, idempotent=True)
    def callgraph_find_root_paths(
        call: mcp.ToolCall,
        target: mcp.Address,
        max_paths: PositivePaths = 100,
        max_depth: NonNegativeDepth = 50,
        max_states: PositiveStates = 5_000,
        max_edges: PositiveEdges = 20_000,
        max_references_per_function: PositiveReferences = 500,
    ) -> dict:
        """Discover bounded caller paths to a function with root classifications.

        Callback references are possible paths, not proven calls. Inspect
        truncated and truncation_reasons before making reachability claims.

        :param target: Target function address, symbol, or address inside a function.
        :param max_paths: Maximum classified paths returned.
        :param max_depth: Maximum caller edges in one path.
        :param max_states: Maximum traversal states expanded.
        :param max_edges: Maximum caller/reference edges examined across the search.
        :param max_references_per_function: Maximum callers or references followed per function.
        """
        return root_paths(
            call,
            target,
            max_paths,
            max_depth,
            max_states,
            max_edges,
            max_references_per_function,
        )[2]

    @mcp.tool()
    def callgraph_draw_paths(
        call: mcp.ToolCall,
        source: mcp.Address,
        target: mcp.Address,
        blacklisted: list[str] | None = None,
        max_paths: PositivePaths = 100,
        max_depth: NonNegativeDepth = 50,
        max_states: PositiveStates = 5_000,
        max_edges: PositiveEdges = 20_000,
        max_references_per_function: PositiveReferences = 500,
    ) -> dict:
        """Find and display bounded call paths between two functions.

        :param source: Source function address, symbol, or address inside a function.
        :param target: Target function address, symbol, or address inside a function.
        :param blacklisted: Exact callee names to exclude while traversing.
        :param max_paths: Maximum paths returned and drawn.
        :param max_depth: Maximum callee edges in one path.
        :param max_states: Maximum traversal states expanded.
        :param max_edges: Maximum callee edges examined across the search.
        :param max_references_per_function: Maximum callees followed from one function.
        """
        return draw_result(
            *between_paths(
                call,
                source,
                target,
                blacklisted,
                max_paths,
                max_depth,
                max_states,
                max_edges,
                max_references_per_function,
            )
        )

    @mcp.tool()
    def callgraph_draw_root_paths(
        call: mcp.ToolCall,
        target: mcp.Address,
        max_paths: PositivePaths = 100,
        max_depth: NonNegativeDepth = 50,
        max_states: PositiveStates = 5_000,
        max_edges: PositiveEdges = 20_000,
        max_references_per_function: PositiveReferences = 500,
    ) -> dict:
        """Discover and display bounded paths from roots to a function.

        :param target: Target function address, symbol, or address inside a function.
        :param max_paths: Maximum classified paths returned and drawn.
        :param max_depth: Maximum caller edges in one path.
        :param max_states: Maximum traversal states expanded.
        :param max_edges: Maximum caller/reference edges examined across the search.
        :param max_references_per_function: Maximum callers or references followed per function.
        """
        return draw_result(
            *root_paths(
                call,
                target,
                max_paths,
                max_depth,
                max_states,
                max_edges,
                max_references_per_function,
            )
        )

    @mcp.tool(read_only=True, idempotent=True)
    def callgraph_export_graphml(
        call: mcp.ToolCall,
        source: mcp.Address,
        target: mcp.Address,
        blacklisted: list[str] | None = None,
        max_paths: PositivePaths = 100,
        max_depth: NonNegativeDepth = 50,
        max_states: PositiveStates = 5_000,
        max_edges: PositiveEdges = 20_000,
        max_references_per_function: PositiveReferences = 500,
    ) -> dict:
        """Return bounded call paths and GraphML XML without writing a file.

        :param source: Source function address, symbol, or address inside a function.
        :param target: Target function address, symbol, or address inside a function.
        :param blacklisted: Exact callee names to exclude while traversing.
        :param max_paths: Maximum paths returned and exported.
        :param max_depth: Maximum callee edges in one path.
        :param max_states: Maximum traversal states expanded.
        :param max_edges: Maximum callee edges examined across the search.
        :param max_references_per_function: Maximum callees followed from one function.
        """
        _, graph, result, _ = between_paths(
            call,
            source,
            target,
            blacklisted,
            max_paths,
            max_depth,
            max_states,
            max_edges,
            max_references_per_function,
        )
        return graphml_result(graph, result)

    @mcp.tool(read_only=True, idempotent=True)
    def callgraph_export_root_graphml(
        call: mcp.ToolCall,
        target: mcp.Address,
        max_paths: PositivePaths = 100,
        max_depth: NonNegativeDepth = 50,
        max_states: PositiveStates = 5_000,
        max_edges: PositiveEdges = 20_000,
        max_references_per_function: PositiveReferences = 500,
    ) -> dict:
        """Return bounded root paths and GraphML XML without writing a file.

        :param target: Target function address, symbol, or address inside a function.
        :param max_paths: Maximum classified paths returned and exported.
        :param max_depth: Maximum caller edges in one path.
        :param max_states: Maximum traversal states expanded.
        :param max_edges: Maximum caller/reference edges examined across the search.
        :param max_references_per_function: Maximum callers or references followed per function.
        """
        _, graph, result, _ = root_paths(
            call,
            target,
            max_paths,
            max_depth,
            max_states,
            max_edges,
            max_references_per_function,
        )
        return graphml_result(graph, result)

    return (
        callgraph_find_paths,
        callgraph_find_root_paths,
        callgraph_draw_paths,
        callgraph_draw_root_paths,
        callgraph_export_graphml,
        callgraph_export_root_graphml,
    )
