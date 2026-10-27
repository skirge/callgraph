from binaryninja import Function, SymbolType, log
from binaryninjaui import Sidebar, SidebarWidget, SidebarWidgetType, UIActionHandler, UIContext
from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QImage, QPainter, QFont, QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

SIDEBAR_NAME = "Callgraph"
FUNC_ROLE = Qt.UserRole
POPULATED_ROLE = Qt.UserRole + 1
SITE_ROLE = Qt.UserRole + 2


class CallgraphSidebarWidget(SidebarWidget):
    def __init__(self, name, frame, data):
        SidebarWidget.__init__(self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)
        self.bv = data
        self.graphs = {}
        self.limit = 1000

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Function", "Address"])
        self.tree.setUniformRowHeights(True)
        self.tree.setExpandsOnDoubleClick(False)
        self.tree.itemExpanded.connect(self._populate)
        self.tree.itemDoubleClicked.connect(self._navigate)

        expand_button = QPushButton("Expand all")
        expand_button.clicked.connect(self._expand_selected)
        remove_button = QPushButton("Remove")
        remove_button.clicked.connect(self._remove_selected)
        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self._clear)

        buttons = QHBoxLayout()
        buttons.addStretch()
        buttons.addWidget(expand_button)
        buttons.addWidget(remove_button)
        buttons.addWidget(clear_button)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addLayout(buttons)
        layout.addWidget(self.tree)
        self.setLayout(layout)

    def add_graph(self, graph, starts, target, limit, title):
        self.limit = limit
        root = QTreeWidgetItem([title, ""])
        font = root.font(0)
        font.setBold(True)
        root.setFont(0, font)
        self.graphs[id(root)] = (graph, target)
        self.tree.insertTopLevelItem(0, root)

        start_items = []
        for start, label in starts:
            item = self._make_item(start, graph, target)
            if label:
                item.setText(0, f"{start.name} [{label}]")
            root.addChild(item)
            start_items.append(item)
        root.setExpanded(True)
        self._expand_recursive(start_items, limit)
        self.tree.setCurrentItem(root)
        self.tree.resizeColumnToContents(0)

    def _graph_for(self, item):
        while item.parent() is not None:
            item = item.parent()
        return self.graphs.get(id(item), (None, None))

    def _make_item(self, func, graph, target, reference=False, sites=None):
        item = QTreeWidgetItem([func.name, hex(func.start)])
        item.setData(0, FUNC_ROLE, func.start)
        item.setData(0, POPULATED_ROLE, False)
        if sites is not None:
            self._set_sites(item, sites)
        if func.symbol.type == SymbolType.ImportedFunctionSymbol:
            item.setForeground(0, QColor(237, 223, 179))
        font = item.font(0)
        if reference:
            item.setText(0, f"{func.name} [ref]")
            item.setToolTip(0, "Referenced by the parent (e.g. callback pointer), not called directly")
            font.setItalic(True)
        if func == target:
            font.setBold(True)
        item.setFont(0, font)
        if func != target and graph.out_degree(func) > 0:
            item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
        return item

    def _set_sites(self, item, sites):
        if not sites:
            item.setText(1, "")
            return
        extra = f" (+{len(sites) - 1})" if len(sites) > 1 else ""
        item.setText(1, f"{sites[0]:#x}{extra}")
        item.setData(1, SITE_ROLE, sites[0])
        item.setToolTip(1, "\n".join(f"{site:#x}" for site in sites))

    def _call_sites_by_callee(self, func):
        sites = {}
        for site in func.call_sites:
            for callee in self.bv.get_callees(site.address, site.function, site.arch):
                sites.setdefault(callee, set()).add(site.address)
        return sites

    def _reference_sites(self, func, callee):
        return {
            ref.address
            for ref in self.bv.get_code_refs(callee.start)
            if ref.function is not None and ref.function.start == func.start
        }

    def _function_of(self, item):
        addr = item.data(0, FUNC_ROLE)
        if addr is None or self.bv is None:
            return None
        return self.bv.get_function_at(addr)

    def _ancestor_addrs(self, item):
        addrs = set()
        while item is not None:
            addr = item.data(0, FUNC_ROLE)
            if addr is not None:
                addrs.add(addr)
            item = item.parent()
        return addrs

    def _populate(self, item):
        if item.data(0, FUNC_ROLE) is None or item.data(0, POPULATED_ROLE):
            return
        item.setData(0, POPULATED_ROLE, True)
        graph, target = self._graph_for(item)
        func = self._function_of(item)
        if graph is None or func is None or func not in graph:
            return
        ancestors = self._ancestor_addrs(item)
        call_sites = None
        for callee in sorted(graph.successors(func), key=lambda f: f.name):
            if callee.start in ancestors:
                continue
            reference = graph.edges[func, callee].get("reference", False)
            if reference:
                sites = self._reference_sites(func, callee)
            else:
                if call_sites is None:
                    call_sites = self._call_sites_by_callee(func)
                sites = call_sites.get(callee.start, set())
            item.addChild(
                self._make_item(callee, graph, target, reference, sorted(sites))
            )
        item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicatorWhenChildless)

    def _expand_recursive(self, items, limit):
        stack = list(reversed(items))
        count = 0
        while stack and count < limit:
            current = stack.pop()
            current.setExpanded(True)
            count += 1
            stack.extend(current.child(i) for i in reversed(range(current.childCount())))
        if stack:
            log.log_warn(f"Callgraph: stopped expanding tree after {limit} nodes")

    def _expand_selected(self):
        item = self.tree.currentItem()
        if item is not None:
            self._expand_recursive([item], self.limit)

    def _remove_selected(self):
        item = self.tree.currentItem()
        if item is None:
            return
        while item.parent() is not None:
            item = item.parent()
        self.graphs.pop(id(item), None)
        self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(item))

    def _clear(self):
        self.graphs.clear()
        self.tree.clear()

    def _navigate(self, item, column):
        addr = item.data(0, FUNC_ROLE)
        if column == 1 and item.data(1, SITE_ROLE) is not None:
            addr = item.data(1, SITE_ROLE)
        if addr is None or self.bv is None:
            return
        frame = _find_frame(self.bv)
        if frame is not None:
            frame.navigate(self.bv, addr)

    def notifyViewChanged(self, view_frame):
        if view_frame is not None:
            self.bv = view_frame.actionContext().binaryView

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)


class CallgraphSidebarWidgetType(SidebarWidgetType):
    def __init__(self):
        icon = QImage(56, 56, QImage.Format_RGB32)
        icon.fill(0)
        p = QPainter()
        p.begin(icon)
        p.setFont(QFont("Open Sans", 40))
        p.setPen(QColor(255, 255, 255, 255))
        p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "CG")
        p.end()
        SidebarWidgetType.__init__(self, icon, SIDEBAR_NAME)

    def createWidget(self, frame, data):
        return CallgraphSidebarWidget(SIDEBAR_NAME, frame, data)


def _candidate_frames():
    contexts = [UIContext.activeContext()] + list(UIContext.allContexts())
    for context in contexts:
        if context is None:
            continue
        yield context.getCurrentViewFrame()
        for tab in context.getTabs():
            yield context.getViewFrameForTab(tab)


def _find_frame(bv):
    fallback = None
    for frame in _candidate_frames():
        if frame is None:
            continue
        frame_bv = frame.getCurrentBinaryView()
        if frame_bv is not None and frame_bv.file == bv.file:
            return frame
        fallback = fallback or frame
    return fallback


def show_graph(bv, graph, starts, target: Function, limit: int, title: str):
    frame = _find_frame(bv)
    if frame is None:
        log.log_error("Callgraph: no active view frame to show sidebar in")
        return False
    sidebar = frame.getSidebar()
    sidebar.activate(SIDEBAR_NAME)
    widget = sidebar.widget(SIDEBAR_NAME)
    if not isinstance(widget, CallgraphSidebarWidget):
        log.log_error("Callgraph: sidebar widget not available")
        return False
    widget.bv = bv
    widget.add_graph(graph, starts, target, limit, title)
    return True


Sidebar.addSidebarWidgetType(CallgraphSidebarWidgetType())
