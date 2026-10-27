# Call graph plugin

Another call graph plugin.
Allows to print/draw graphs with paths between two selected functions (usually: one which processes some insecure input and some insecure sink)

"Draw" commands show the paths as a tree in the **Callgraph** sidebar. Each query is added as a separate top-level entry; double-click a function to navigate to it. Use "Expand all" on a selected node, "Remove" to drop a query, and "Clear" to reset the tree.

The plugin also exposes six tools through Binary Ninja's native MCP server:

| Tool | Operation |
| --- | --- |
| `callgraph_find_paths` | Find paths between two functions. |
| `callgraph_find_root_paths` | Find classified paths from discovered roots. |
| `callgraph_draw_paths` | Find and draw paths between two functions. |
| `callgraph_draw_root_paths` | Find and draw paths from discovered roots. |
| `callgraph_export_graphml` | Return paths and GraphML XML. |
| `callgraph_export_root_graphml` | Return root paths and GraphML XML. |

`source` and `target` accept Binary Ninja address expressions, including symbol
names and addresses inside functions. Between-function tools also accept exact
callee names in `blacklisted`.

Every MCP search is bounded. The default limits are 100 returned paths, 50
caller/callee edges per path, 5,000 traversal states, 20,000 examined edges, and
500 callers/callees/references from any one function. Each value is an optional
tool argument (`max_paths`, `max_depth`, `max_states`, `max_edges`, and
`max_references_per_function`). Results include the effective limits, work
counters, `truncated`, and `truncation_reasons`; a truncated empty result is not
evidence that no path exists.

The same defaults are available in **Settings > Callgraph** for UI searches.
These limits prevent a high-fan-in sink such as `memcpy` in a large binary from
causing unbounded path enumeration. MCP schemas also impose hard upper bounds,
so an accidental oversized request cannot disable all safeguards.

Drawing requires the Binary Ninja UI and still observes the separate graph-node
display limit. GraphML tools return XML in the `graphml` field and do not write a
file. On older Binary Ninja builds without `binaryninja.mcp`, the UI commands
remain available and the plugin logs that MCP registration was skipped.

