#Binary Ninja version of alleycat
#
from binaryninja import *
from binaryninja.plugin import *
from binaryninja.interaction import *
from binaryninja.mainthread import execute_on_main_thread_and_wait
import networkx as nx

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

def show_tree(g: nx.DiGraph, start_function: Function, target_function: Function):
    if not core_ui_enabled():
        log.log(LogLevel.ErrorLog, "Showing call trees requires the Binary Ninja UI")
        return
    execute_on_main_thread_and_wait(
        lambda: sidebar.show_graph(g, start_function, target_function, ALLEYCAT_LIMIT))

def do(bv, start_function, target_function, blacklisted = [], textmode = True, drawmode = False):
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
        if drawmode:
            nodes_between_set = {node for path in paths for node in path}
            sg = call_graph.subgraph(nodes_between_set).copy()
            if sg.number_of_nodes() > ALLEYCAT_LIMIT:
                if show_message_box(f"Graph contains large number of nodes:{sg.number_of_nodes()}, do you want to show it?", \
                                       MessageBoxButtonSet.YesNoButtonSet, \
                                       MessageBoxIcon.QuestionIcon) == \
                                       MessageBoxButtonResult.NoButton:
                    return
            show_tree(sg, start_function, target_function)
            log.log(LogLevel.InfoLog, "Graph drawing done")
    else:
        print(f"No paths found between {start_function.name} and {target_function.name}.")

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
                       "Show all paths between two functions as a tree in the Callgraph sidebar",\
                       draw_paths_ask)
PluginCommand.register_for_function("Graphs\\Draw paths from this to other function",\
                                    "Show all paths from currently selected function to other function as a tree in the Callgraph sidebar",\
                                    draw_paths_from_this)
PluginCommand.register_for_function("Graphs\\Draw paths from other function to this",\
                                    "Show all paths from other function to currently selected function as a tree in the Callgraph sidebar",\
                                    draw_paths_to_this)

