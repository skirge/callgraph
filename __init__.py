#Binary Ninja version of alleycat
#
from binaryninja import *
from binaryninja.plugin import *
from binaryninja.interaction import *
import networkx as nx

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

ALLEYCAT_LIMIT = Settings().get_integer("callgraph.limit")

def build_call_graph(view, call_graph, visited, current_function, termination, blacklisted):
    #if current_function.start in visited:
    #    return
    if termination.start == current_function.start:
        return
    visited.add(current_function.start)
    for callee in current_function.callees:
        # print(caller)
        # recursion
        if callee.start == current_function.start:
            print(f"Function {callee.name} is recursive!")
            continue
        if callee.start in visited:
            continue
        if callee.name in blacklisted:
            continue
        call_graph.add_edge(current_function, callee)
        build_call_graph(view, call_graph, visited, callee, termination, blacklisted)


def all_paths(call_graph, start_func, target_func):
    try:
        paths = nx.all_simple_paths(call_graph, source=start_func, target=target_func)
        return list(paths)
    except nx.NodeNotFound:
        return []

def get_function_name(view, address):
    if isinstance(address, Function):
        return address.name
    function = view.get_function_at(address)
    return f"{function.name}@{hex(address)}" if function else hex(address)

# stolen from Ariadne
def render_flowgraph(bv: BinaryView, g: nx.DiGraph, title: str=''):
    """Render arbitrary networkx graph"""
    flowgraph = FlowGraph()
    flowgraph_nodes: Dict[Function, FlowGraphNode] = {}

    # encapsulate check/add with a helper func for clarity
    def add_node(node_func: Function):
        if node_func not in flowgraph_nodes:
            new_node = FlowGraphNode(flowgraph)
            # h/t @joshwatson on how to distinguish imports, your implementation was better
            if node_func.symbol.type == SymbolType.ImportedFunctionSymbol:
                token_type = InstructionTextTokenType.ImportToken
            else:
                token_type = InstructionTextTokenType.CodeSymbolToken
            cur_func_name = get_function_name(bv, node_func)
            func_token = InstructionTextToken(token_type, cur_func_name, node_func.start)
            new_node.lines = [DisassemblyTextLine([func_token])]

            flowgraph.append(new_node)
            flowgraph_nodes[node_func] = new_node
            return new_node
        return flowgraph_nodes[node_func]

    # one traversal that adds islands and nodes with edges
    for node_func in g.nodes:
        src_flowgraph_node = add_node(node_func)
        for src, dst in g.out_edges(node_func):
            dst_flowgraph_node = add_node(dst)
            src_flowgraph_node.add_outgoing_edge(BranchType.CallDestination, dst_flowgraph_node)

    bv.show_graph_report(title, flowgraph)

def do(bv, start_function, target_function, blacklisted = [], textmode = True, drawmode = False, savemode = False):
    # Build the call graph
    call_graph = nx.DiGraph()
    visited = set()
    build_call_graph(bv, call_graph, visited, start_function, target_function, blacklisted)
    #print("Call graph built!")
    # Check if paths are possible between the two functions
    paths = all_paths(call_graph, start_function, target_function)
    #print("Got all paths!")
    if paths:
        if textmode:
            report = ""
            for path in paths:
                function_names = [func.name for func in path]
                report += " -> ".join(function_names)
                report += "\n\n"
            bv.show_plain_text_report(f"Paths found between {start_function.name} and {target_function.name}",report)
        if drawmode or savemode:
            nodes_between_set = {node for path in paths for node in path}
            sg = call_graph.subgraph(nodes_between_set)
            if drawmode:
                if sg.number_of_nodes() > ALLEYCAT_LIMIT:
                    if show_message_box(f"Graph contains large number of nodes:{sg.number_of_nodes()}, do you want to show it?", \
                                           MessageBoxButtonSet.YesNoButtonSet, \
                                           MessageBoxIcon.QuestionIcon) == \
                                           MessageBoxButtonResult.NoButton:
                        return
                render_flowgraph(bv, sg, f"{start_function.name} -> {target_function.name}")
            if savemode:
                # ask file
                file_name = get_save_filename_input("File name to save","graphml","graph.graphml")
                if file_name is None:
                    return
                nx.write_graphml_lxml(sg,file_name)
            del sg
            del call_graph
            log.log(LogLevel.InfoLog, "Graph drawing done")
    else:
        print(f"No paths found between {start_function.name} and {target_function.name}.")

def get_blacklisted_functions():
    return list()

def ask_both(bv, textmode, drawmode, savemode):
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
       textmode, drawmode, savemode )

def ask_target(bv, function, textmode, drawmode, savemode):
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
       textmode, drawmode, savemode )

def ask_source(bv, function, textmode, drawmode, savemode):
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
       textmode, drawmode, savemode )

def generate_text_paths_ask(bv):
    ask_both(bv, True, False, False)

def generate_text_paths_from_this(bv, function):
    ask_target(bv, function, True, False, False)

def generate_text_paths_to_this(bv, function):
    ask_source(bv, function, True, False, False)

def draw_paths_ask(bv):
    ask_both(bv, False, True, False)

def draw_paths_from_this(bv, function):
    ask_target(bv, function, False, True, False)

def draw_paths_to_this(bv, function):
    ask_source(bv, function, False, True, False)

def save_gml_paths_ask(bv):
    ask_both(bv, False, False, True)

def save_gml_paths_to_this(bv, function):
    ask_source(bv, function, False, False, True)

def save_gml_paths_from_this(bv, function):
    ask_target(bv, function, False, False, True)

PluginCommand.register("Graphs\\Generate paths between two functions",\
                       "Generate all paths between two functions in text format",\
                       generate_text_paths_ask)
PluginCommand.register_for_function("Graphs\\Generate paths from this to other function",\
                                    "Generate all paths between currently selected function and other function",\
                                    generate_text_paths_from_this)
PluginCommand.register_for_function("Graphs\\Generate paths from other function to this",\
                                    "Generate all paths from other function to currently selected function",\
                                    generate_text_paths_to_this)
PluginCommand.register("Graphs\\Draw paths between two functions",\
                       "Show all paths between two functions",\
                       draw_paths_ask)
PluginCommand.register_for_function("Graphs\\Draw paths from this to other function",\
                                    "Show all paths from currently selected function to other function",\
                                    draw_paths_from_this)
PluginCommand.register_for_function("Graphs\\Draw paths from other function to this",\
                                    "Show all paths from other function to currently selected function",\
                                    draw_paths_to_this)
PluginCommand.register("Graphs\\Save Graphml with paths between two functions",\
                       "Save graph with all paths in GraphML format",\
                       save_gml_paths_ask)
PluginCommand.register_for_function("Graphs\\Save Graphml with paths from this function to other function",\
                                    "Save graph in GraphML format with all paths from currently selected function to other function",\
                                    save_gml_paths_from_this)
PluginCommand.register_for_function("Graphs\\Save Graphml with paths from other function to this function",\
                                    "Save graph in GraphML format with all paths from other function to currently selected function",\
                                    save_gml_paths_to_this)

