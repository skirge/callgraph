# Binary Ninja version of alleycat

from itertools import pairwise

from binaryninja import *
from binaryninja.plugin import *
from binaryninja.interaction import *
from binaryninja.mainthread import execute_on_main_thread_and_wait
import networkx as nx

from .search import SearchLimits, find_paths_between, find_paths_from_roots

if core_ui_enabled():
    from . import sidebar

Settings().register_group("callgraph", "Callgraph")
Settings().register_setting("callgraph.limit", """
    {
        "title" : "Graph node limit",
        "type" : "number",
        "default" : 1000,
        "description" : "Graph node limit to prevent displaying very large graphs",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """)
Settings().register_setting("callgraph.pathMaxPaths", """
    {
        "title" : "Maximum returned paths",
        "type" : "number",
        "default" : 100,
        "minValue" : 1,
        "maxValue" : 1000,
        "description" : "Maximum paths returned by a search before it is truncated",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """)
Settings().register_setting("callgraph.pathMaxDepth", """
    {
        "title" : "Path maximum depth",
        "type" : "number",
        "default" : 50,
        "minValue" : 0,
        "maxValue" : 1000,
        "description" : "Maximum callee edges in a path between two functions",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """)
Settings().register_setting("callgraph.rootPathMaxDepth", """
    {
        "title" : "Root path maximum depth",
        "type" : "number",
        "default" : 50,
        "minValue" : 0,
        "maxValue" : 1000,
        "description" : "Maximum caller edges in a path from a discovered root",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """)
Settings().register_setting("callgraph.searchMaxStates", """
    {
        "title" : "Search state limit",
        "type" : "number",
        "default" : 5000,
        "minValue" : 1,
        "maxValue" : 100000,
        "description" : "Maximum path traversal states expanded by one search",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """)
Settings().register_setting("callgraph.searchMaxEdges", """
    {
        "title" : "Search edge limit",
        "type" : "number",
        "default" : 20000,
        "minValue" : 1,
        "maxValue" : 500000,
        "description" : "Maximum caller or callee edges examined by one search",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """)
Settings().register_setting("callgraph.referencesPerFunction", """
    {
        "title" : "References per function limit",
        "type" : "number",
        "default" : 500,
        "minValue" : 1,
        "maxValue" : 10000,
        "description" : "Maximum callers, callees, or fallback references followed from one function",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """)

ALLEYCAT_LIMIT = Settings().get_integer("callgraph.limit")


def get_search_limits(max_depth=None, max_paths=None):
    settings = Settings()
    return SearchLimits(
        max_paths=(
            settings.get_integer("callgraph.pathMaxPaths")
            if max_paths is None
            else max_paths
        ),
        max_depth=(
            settings.get_integer("callgraph.pathMaxDepth")
            if max_depth is None
            else max_depth
        ),
        max_states=settings.get_integer("callgraph.searchMaxStates"),
        max_edges=settings.get_integer("callgraph.searchMaxEdges"),
        max_references_per_function=settings.get_integer(
            "callgraph.referencesPerFunction"
        ),
    )


def build_path_graph(paths):
    graph = nx.DiGraph()
    for path in paths:
        graph.add_nodes_from(path)
        graph.add_edges_from(pairwise(path))
    return graph


def search_warning(stats):
    if not stats.truncated:
        return ""
    reasons = ", ".join(sorted(stats.truncation_reasons))
    return f"Results truncated by: {reasons}."

def get_function_name(view, address):
    if isinstance(address, Function):
        return address.name
    function = view.get_function_at(address)
    return f"{function.name}@{hex(address)}" if function else hex(address)

def show_tree(g: nx.DiGraph, start_function: Function, target_function: Function):
    if not core_ui_enabled():
        log.log(LogLevel.ErrorLog, "Showing call trees requires the Binary Ninja UI")
        return
    execute_on_main_thread_and_wait(
        lambda: sidebar.show_graph(g, start_function, target_function, ALLEYCAT_LIMIT))

def do(bv, start_function, target_function, blacklisted=None, textmode=True, drawmode=False):
    result = find_paths_between(
        start_function,
        target_function,
        set(blacklisted or ()),
        get_search_limits(),
    )
    paths = result.paths
    if paths:
        if textmode:
            report = search_warning(result.stats)
            if report:
                report += "\n\n"
            for path in paths:
                function_names = [func.name for func in path]
                report += " -> ".join(function_names)
                report += "\n\n"
            bv.show_plain_text_report(
                f"Paths found between {start_function.name} and {target_function.name}",
                report,
            )
        if drawmode:
            sg = build_path_graph(paths)
            if sg.number_of_nodes() > ALLEYCAT_LIMIT:
                if (
                    show_message_box(
                        f"Graph contains {sg.number_of_nodes()} nodes. Show it?",
                        MessageBoxButtonSet.YesNoButtonSet,
                        MessageBoxIcon.QuestionIcon,
                    )
                    == MessageBoxButtonResult.NoButton
                ):
                    return
            show_tree(sg, start_function, target_function)
            log.log(LogLevel.InfoLog, "Graph drawing done")
    else:
        print(f"No paths found between {start_function.name} and {target_function.name}.")
    if result.stats.truncated:
        log.log_warn(f"Callgraph: {search_warning(result.stats)}")


def root_search_limits():
    settings = Settings()
    return SearchLimits(
        max_paths=settings.get_integer("callgraph.pathMaxPaths"),
        max_depth=settings.get_integer("callgraph.rootPathMaxDepth"),
        max_states=settings.get_integer("callgraph.searchMaxStates"),
        max_edges=settings.get_integer("callgraph.searchMaxEdges"),
        max_references_per_function=settings.get_integer(
            "callgraph.referencesPerFunction"
        ),
    )


def find_root_paths(bv, target_function, limits=None, is_cancelled=None):
    bindings = (SymbolBinding.GlobalBinding, SymbolBinding.WeakBinding)
    return find_paths_from_roots(
        bv, target_function, bindings, limits or root_search_limits(), is_cancelled
    )


def format_root_paths(paths):
    return "\n\n".join(
        f"[{root_kind}]\n{' -> '.join(function.name for function in path)}"
        for root_kind, path in paths
    )


def generate_paths_from_roots(bv, function):
    result = find_root_paths(bv, function)
    report = search_warning(result.stats)
    if report and result.paths:
        report += "\n\n"
    report += format_root_paths(result.paths)
    bv.show_plain_text_report(
        f"Paths from discovered roots to {function.name}", report or "No paths found."
    )


def draw_paths_from_roots(bv, function):
    result = find_root_paths(bv, function)
    graph = build_path_graph(path for _, path in result.paths)
    if graph.number_of_nodes() > ALLEYCAT_LIMIT:
        if show_message_box(
            f"Graph contains large number of nodes:{graph.number_of_nodes()}, do you want to show it?",
            MessageBoxButtonSet.YesNoButtonSet,
            MessageBoxIcon.QuestionIcon,
        ) == MessageBoxButtonResult.NoButton:
            return
    render_flowgraph(bv, graph, f"Discovered roots -> {function.name}")


def render_flowgraph(bv, graph, title=""):
    def show():
        flowgraph = FlowGraph()
        nodes = {}

        def add_node(function):
            if function not in nodes:
                node = FlowGraphNode(flowgraph)
                token_type = (
                    InstructionTextTokenType.ImportToken
                    if function.symbol.type == SymbolType.ImportedFunctionSymbol
                    else InstructionTextTokenType.CodeSymbolToken
                )
                token = InstructionTextToken(token_type, function.name, function.start)
                node.lines = [DisassemblyTextLine([token])]
                flowgraph.append(node)
                nodes[function] = node
            return nodes[function]

        for function in graph.nodes:
            source_node = add_node(function)
            for _, target in graph.out_edges(function):
                source_node.add_outgoing_edge(BranchType.CallDestination, add_node(target))
        bv.show_graph_report(title, flowgraph)

    execute_on_main_thread_and_wait(show)

def get_blacklisted_functions():
    return list()

def ask_both(bv, textmode, drawmode):
    addr_from = bv.get_address_input("Choose source function", "Source function")
    if addr_from is None:
        log.log(LogLevel.ErrorLog, "No source function provided")
        return
    start_function = bv.get_function_at(addr_from)
    if not start_function:
        log.log(LogLevel.ErrorLog, "Start function doesn't exists!")
        return
    addr_to = bv.get_address_input("Choose target function", "Target function")
    if addr_to is None:
        log.log(LogLevel.ErrorLog, "No target function provided")
        return
    target_function = bv.get_function_at(addr_to)
    if not target_function:
        log.log(LogLevel.ErrorLog, "Target function doesn't exitsts!")
        return
    do(bv, start_function, target_function, get_blacklisted_functions(),\
       textmode, drawmode)

def ask_target(bv, function, textmode, drawmode):
    start_function = function
    if not start_function:
        log.log(LogLevel.ErrorLog, "Start function doesn't exists!")
        return
    addr_to = bv.get_address_input("Choose target function", "Target function")
    if addr_to is None:
        log.log(LogLevel.ErrorLog, "No target function provided")
        return
    target_function = bv.get_function_at(addr_to)
    if not target_function:
        log.log(LogLevel.ErrorLog, "Target function doesn't exitsts!")
        return
    do(bv, start_function, target_function, get_blacklisted_functions(),\
       textmode, drawmode)

def ask_source(bv, function, textmode, drawmode):
    addr_from = bv.get_address_input("Choose source function", "Source function")
    if addr_from is None:
        log.log(LogLevel.ErrorLog, "No source function provided")
        return
    start_function = bv.get_function_at(addr_from)
    if not start_function:
        log.log(LogLevel.ErrorLog, "Start function doesn't exists!")
        return
    target_function = function
    if not target_function:
        log.log(LogLevel.ErrorLog, "Target function doesn't exitsts!")
        return
    do(bv, start_function, target_function, get_blacklisted_functions(),\
       textmode, drawmode)

def generate_text_paths_ask(bv):
    ask_both(bv, True, False)

def generate_text_paths_from_this(bv, function):
    ask_target(bv, function, True, False)

def generate_text_paths_to_this(bv, function):
    ask_source(bv, function, True, False)

def draw_paths_ask(bv):
    ask_both(bv, False, True)

def draw_paths_from_this(bv, function):
    ask_target(bv, function, False, True)

def draw_paths_to_this(bv, function):
    ask_source(bv, function, False, True)

PluginCommand.register(
    "Graphs\\Generate paths between two functions",
    "Generate bounded paths between two functions in text format",
    generate_text_paths_ask,
)
PluginCommand.register_for_function(
    "Graphs\\Generate paths from this to other function",
    "Generate bounded paths from the selected function to another function",
    generate_text_paths_from_this,
)
PluginCommand.register_for_function(
    "Graphs\\Generate paths from other function to this",
    "Generate bounded paths from another function to the selected function",
    generate_text_paths_to_this,
)
PluginCommand.register(
    "Graphs\\Draw paths between two functions",
    "Show bounded paths between two functions in the Callgraph sidebar",
    draw_paths_ask,
)
PluginCommand.register_for_function(
    "Graphs\\Draw paths from this to other function",
    "Show bounded paths from the selected function in the Callgraph sidebar",
    draw_paths_from_this,
)
PluginCommand.register_for_function(
    "Graphs\\Draw paths from other function to this",
    "Show bounded paths to the selected function in the Callgraph sidebar",
    draw_paths_to_this,
)
PluginCommand.register_for_function(
    "Graphs\\Generate paths from discovered roots to this",
    "Generate bounded caller paths from discovered roots to this function",
    generate_paths_from_roots,
)
PluginCommand.register_for_function(
    "Graphs\\Draw paths from discovered roots to this",
    "Draw bounded caller paths from discovered roots to this function",
    draw_paths_from_roots,
)


try:
    import binaryninja.mcp  # noqa: F401 -- Probe for the optional native plugin API.
except ModuleNotFoundError as exc:
    if exc.name != "binaryninja.mcp":
        raise
    log_warn("Callgraph MCP tools require a Binary Ninja build with binaryninja.mcp.")
else:
    from .mcp_tools import register_tools

    _mcp_tools = register_tools()

