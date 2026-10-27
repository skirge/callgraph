"""Bounded call-graph searches shared by the UI and MCP adapters."""

from dataclasses import dataclass, field
from typing import Callable, Iterable


ROOT_KIND_PRIORITY = {
    "ENTRY": 0,
    "EXPORT": 1,
    "NO_CALLERS_CODE_REF": 2,
    "NO_CALLERS_DATA_REF": 2,
    "NO_CALLERS_XREF": 2,
    "NO_CALLERS": 2,
    "CYCLE": 3,
    "MAX_DEPTH": 4,
    "CALLBACK": 5,
}


class SearchCancelled(Exception):
    """Raised when the caller cancels a graph search."""


@dataclass(frozen=True)
class SearchLimits:
    max_paths: int = 100
    max_depth: int = 50
    max_states: int = 5_000
    max_edges: int = 20_000
    max_references_per_function: int = 500


@dataclass
class SearchStats:
    states_expanded: int = 0
    edges_examined: int = 0
    unique_functions: set[int] = field(default_factory=set)
    truncation_reasons: set[str] = field(default_factory=set)

    @property
    def truncated(self):
        return bool(self.truncation_reasons)


@dataclass
class PathSearchResult:
    paths: list
    stats: SearchStats


@dataclass
class RootPathSearchResult:
    paths: list
    stats: SearchStats
    reference_edges: set[tuple[int, int]] = field(default_factory=set)


def _bounded_unique_functions(functions: Iterable, limit: int):
    result = []
    seen = set()
    iterator = iter(functions)
    examined = 0
    while examined <= limit:
        try:
            function = next(iterator)
        except StopIteration:
            return result, False
        examined += 1
        if examined > limit:
            return result, True
        if function.start in seen:
            continue
        seen.add(function.start)
        result.append(function)
    return result, False


def _callers(function):
    """Avoid materializing every caller Function when Binary Ninja exposes caller sites."""
    try:
        caller_sites = function.caller_sites
    except AttributeError:
        yield from function.callers
        return
    for reference in caller_sites:
        if reference.function is not None:
            yield reference.function


def _check_cancelled(is_cancelled: Callable[[], bool] | None):
    if is_cancelled is not None and is_cancelled():
        raise SearchCancelled


def _distances_to_target(target, limits, is_cancelled):
    """Map function start -> caller hops to target; None when a limit left the map incomplete."""
    distances = {target.start: 0}
    frontier = [target]
    states = edges = 0
    depth_cut = False
    while frontier:
        next_frontier = []
        for function in frontier:
            _check_cancelled(is_cancelled)
            states += 1
            if states > limits.max_states:
                return None, False
            callers, limited = _bounded_unique_functions(
                _callers(function), limits.max_references_per_function
            )
            if limited:
                return None, False
            distance = distances[function.start]
            for caller in callers:
                edges += 1
                if edges > limits.max_edges:
                    return None, False
                if caller.start in distances:
                    continue
                if distance >= limits.max_depth:
                    depth_cut = True
                    continue
                distances[caller.start] = distance + 1
                next_frontier.append(caller)
        frontier = next_frontier
    return distances, depth_cut


def find_paths_between(
    source,
    target,
    blacklisted: set[str],
    limits: SearchLimits,
    is_cancelled: Callable[[], bool] | None = None,
):
    """Enumerate simple source-to-target paths without first building the whole graph."""
    stats = SearchStats(unique_functions={source.start})
    paths = []
    pending = [(source, [source], {source.start})]

    # Without pruning, depth-first search can spend its whole budget in a callee
    # subtree that never reaches the target.
    distances, depth_cut = _distances_to_target(target, limits, is_cancelled)
    if depth_cut:
        stats.truncation_reasons.add("max_depth")
    if distances is not None and source.start not in distances:
        return PathSearchResult([], stats)

    while pending:
        _check_cancelled(is_cancelled)
        if stats.states_expanded >= limits.max_states:
            stats.truncation_reasons.add("max_states")
            break

        function, path, visited = pending.pop()
        stats.states_expanded += 1

        if function.start == target.start:
            paths.append(path)
            if len(paths) > limits.max_paths:
                stats.truncation_reasons.add("max_paths")
                break
            continue

        if len(path) - 1 >= limits.max_depth:
            stats.truncation_reasons.add("max_depth")
            continue

        callees, limited = _bounded_unique_functions(
            function.callees, limits.max_references_per_function
        )
        if limited:
            stats.truncation_reasons.add("max_references_per_function")

        successors = []
        for callee in callees:
            if stats.edges_examined >= limits.max_edges:
                stats.truncation_reasons.add("max_edges")
                break
            stats.edges_examined += 1
            stats.unique_functions.add(callee.start)
            if callee.name in blacklisted or callee.start in visited:
                continue
            if distances is not None:
                remaining = distances.get(callee.start)
                if remaining is None:
                    continue
                if len(path) + remaining > limits.max_depth:
                    stats.truncation_reasons.add("max_depth")
                    continue
            successors.append(callee)
        if "max_edges" in stats.truncation_reasons:
            break

        pending.extend(
            (callee, [*path, callee], visited | {callee.start})
            for callee in reversed(successors)
        )

    return PathSearchResult(paths[: limits.max_paths], stats)


def _no_caller_root_kind(bv, function, stats, limits):
    code_refs, code_limited = _bounded_unique_references(
        bv.get_code_refs(function.start), limits.max_references_per_function
    )
    data_refs, data_limited = _bounded_values(
        bv.get_data_refs(function.start), limits.max_references_per_function
    )
    if code_limited or data_limited:
        stats.truncation_reasons.add("max_references_per_function")
    has_code_refs = bool(code_refs)
    has_data_refs = bool(data_refs)
    if has_code_refs and has_data_refs:
        return "NO_CALLERS_XREF"
    if has_code_refs:
        return "NO_CALLERS_CODE_REF"
    if has_data_refs:
        return "NO_CALLERS_DATA_REF"
    return "NO_CALLERS"


def _bounded_values(values: Iterable, limit: int):
    result = []
    iterator = iter(values)
    while len(result) <= limit:
        try:
            result.append(next(iterator))
        except StopIteration:
            return result, False
    return result[:limit], True


def _bounded_unique_references(references: Iterable, limit: int):
    result = []
    seen = set()
    iterator = iter(references)
    examined = 0
    while examined <= limit:
        try:
            reference = next(iterator)
        except StopIteration:
            return result, False
        examined += 1
        if examined > limit:
            return result, True
        key = (reference.address, getattr(reference.function, "start", None))
        if key in seen:
            continue
        seen.add(key)
        result.append(reference)
    return result, False


def _callback_callers(bv, function, stats, limits):
    code_refs, limited = _bounded_unique_references(
        bv.get_code_refs(function.start), limits.max_references_per_function
    )
    if limited:
        stats.truncation_reasons.add("max_references_per_function")
    callers = []
    for code_ref in code_refs:
        if stats.edges_examined >= limits.max_edges:
            stats.truncation_reasons.add("max_edges")
            break
        stats.edges_examined += 1
        ref_functions = (
            [code_ref.function]
            if code_ref.function is not None
            else bv.get_functions_containing(code_ref.address)
        )
        callers.extend(ref_functions)
    callers, callers_limited = _bounded_unique_functions(
        callers, limits.max_references_per_function
    )
    if callers_limited:
        stats.truncation_reasons.add("max_references_per_function")
    return callers


def _add_root_path(unique_paths, root_kind, path):
    key = tuple(function.start for function in path)
    existing = unique_paths.get(key)
    if existing is None or ROOT_KIND_PRIORITY[root_kind] < ROOT_KIND_PRIORITY[existing[0]]:
        unique_paths[key] = (root_kind, path)


def find_paths_from_roots(
    bv,
    sink,
    exported_bindings: tuple,
    limits: SearchLimits,
    is_cancelled: Callable[[], bool] | None = None,
):
    """Walk callers toward roots with explicit bounds on every branching dimension."""
    entry_points = {function.start for function in bv.entry_functions}
    unique_paths = {}
    reference_edges = set()
    pending = [(sink, [sink], {sink.start})]
    stats = SearchStats(unique_functions={sink.start})

    while pending:
        _check_cancelled(is_cancelled)
        if len(unique_paths) > limits.max_paths:
            stats.truncation_reasons.add("max_paths")
            break
        if stats.states_expanded >= limits.max_states:
            stats.truncation_reasons.add("max_states")
            break

        function, path, visited = pending.pop()
        stats.states_expanded += 1

        if function.start in entry_points:
            _add_root_path(unique_paths, "ENTRY", path)
            continue

        exported = function.symbol.binding in exported_bindings
        if exported:
            _add_root_path(unique_paths, "EXPORT", path)

        if len(path) - 1 >= limits.max_depth:
            _add_root_path(unique_paths, "MAX_DEPTH", path)
            stats.truncation_reasons.add("max_depth")
            continue

        callers, limited = _bounded_unique_functions(
            _callers(function), limits.max_references_per_function
        )
        if limited:
            stats.truncation_reasons.add("max_references_per_function")

        if not callers:
            callers = _callback_callers(bv, function, stats, limits)
            for caller in callers:
                reference_edges.add((caller.start, function.start))
                _add_root_path(unique_paths, "CALLBACK", [caller, *path])

        if "max_edges" in stats.truncation_reasons:
            break

        if not callers:
            if not exported:
                _add_root_path(
                    unique_paths, _no_caller_root_kind(bv, function, stats, limits), path
                )
            continue

        unvisited = []
        for caller in callers:
            if stats.edges_examined >= limits.max_edges:
                stats.truncation_reasons.add("max_edges")
                break
            stats.edges_examined += 1
            stats.unique_functions.add(caller.start)
            if caller.start not in visited:
                unvisited.append(caller)
        if "max_edges" in stats.truncation_reasons:
            break
        if not unvisited:
            _add_root_path(unique_paths, "CYCLE", path)
            continue

        pending.extend(
            (caller, [caller, *path], visited | {caller.start})
            for caller in reversed(unvisited)
        )

    paths = list(unique_paths.values())
    if len(paths) > limits.max_paths:
        stats.truncation_reasons.add("max_paths")
    return RootPathSearchResult(paths[: limits.max_paths], stats, reference_edges)
