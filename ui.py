from binaryninjaui import UIContext
from PySide6 import QtCore, QtGui, QtWidgets

from .analysis import format_code_reuse, format_software_type


def _addr_item(value):
    """QTableWidgetItem that sorts numerically for hex addresses."""
    item = QtWidgets.QTableWidgetItem()
    item.setData(QtCore.Qt.DisplayRole, hex(value) if isinstance(value, int) else str(value))
    item.setData(QtCore.Qt.UserRole, value)
    return item


def _text_item(value):
    item = QtWidgets.QTableWidgetItem()
    item.setData(QtCore.Qt.DisplayRole, str(value))
    return item


BLOCK_COLUMNS = [
    'Function Address',
    'Function Name',
    'Block Address',
    'End Block Address',
    'Software Type',
    'Code Reuse',
    'Strings',
]

GENE_COLUMNS = [
    'Family / Gene',
    'Software Type',
    'Block Address',
    'Function Address',
    'Function Name',
]


class IntezerBlockTable(QtWidgets.QTableWidget):
    def __init__(self, bv, block_map, parent=None):
        super().__init__(parent)
        self._bv = bv
        self._populate(block_map)

    def _populate(self, block_map):
        self.setColumnCount(len(BLOCK_COLUMNS))
        self.setHorizontalHeaderLabels(BLOCK_COLUMNS)
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.setSortingEnabled(True)
        self.horizontalHeader().setStretchLastSection(True)

        self.setRowCount(len(block_map))
        for row, entry in enumerate(block_map.values()):
            self.setItem(row, 0, _addr_item(entry.get('function_address', 0)))
            self.setItem(row, 1, _text_item(entry.get('function_name', '')))
            self.setItem(row, 2, _addr_item(entry['block_address']))
            self.setItem(row, 3, _addr_item(entry.get('end_block_address', 0)))
            self.setItem(row, 4, _text_item(format_software_type(entry.get('software_type', ''))))
            self.setItem(row, 5, _text_item(format_code_reuse(entry.get('code_reuse', []))))
            self.setItem(row, 6, _text_item(', '.join(entry.get('strings', []))))

        self.resizeColumnsToContents()
        self.cellDoubleClicked.connect(self._on_double_click)

    def _on_double_click(self, row, _col):
        # Navigate to block address on double-click
        addr_item = self.item(row, 2)
        if addr_item:
            addr = addr_item.data(QtCore.Qt.UserRole)
            ctx = UIContext.activeContext()
            if ctx and addr:
                ctx.navigateForBinaryView(self._bv, addr)

    def contextMenuEvent(self, event):
        menu = QtWidgets.QMenu(self)
        copy_action = menu.addAction('Copy cell')
        action = menu.exec_(self.mapToGlobal(event.pos()))
        if action == copy_action:
            items = self.selectedItems()
            if items:
                QtWidgets.QApplication.clipboard().setText(items[0].text())

    def filter(self, text):
        text = text.lower()
        for row in range(self.rowCount()):
            hide = not any(
                text in (self.item(row, col).text().lower() if self.item(row, col) else '')
                for col in range(self.columnCount())
            )
            self.setRowHidden(row, hide)


class IntezerGeneTable(QtWidgets.QTableWidget):
    def __init__(self, bv, block_map, parent=None):
        super().__init__(parent)
        self._bv = bv
        self._populate(block_map)

    def _populate(self, block_map):
        self.setColumnCount(len(GENE_COLUMNS))
        self.setHorizontalHeaderLabels(GENE_COLUMNS)
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.setSortingEnabled(True)
        self.horizontalHeader().setStretchLastSection(True)

        rows = []
        for entry in block_map.values():
            families = entry.get('code_reuse') or []
            if not families:
                families = ['—']
            for family in families:
                rows.append((
                    family,
                    entry.get('software_type', ''),
                    entry['block_address'],
                    entry.get('function_address', 0),
                    entry.get('function_name', ''),
                ))

        self.setRowCount(len(rows))
        for row, (family, stype, block_addr, func_addr, func_name) in enumerate(rows):
            self.setItem(row, 0, _text_item(family))
            self.setItem(row, 1, _text_item(format_software_type(stype)))
            self.setItem(row, 2, _addr_item(block_addr))
            self.setItem(row, 3, _addr_item(func_addr))
            self.setItem(row, 4, _text_item(func_name))

        self.resizeColumnsToContents()
        self.cellDoubleClicked.connect(self._on_double_click)

    def _on_double_click(self, row, _col):
        addr_item = self.item(row, 2)
        if addr_item:
            addr = addr_item.data(QtCore.Qt.UserRole)
            ctx = UIContext.activeContext()
            if ctx and addr:
                ctx.navigateForBinaryView(self._bv, addr)

    def filter(self, text):
        text = text.lower()
        for row in range(self.rowCount()):
            hide = not any(
                text in (self.item(row, col).text().lower() if self.item(row, col) else '')
                for col in range(self.columnCount())
            )
            self.setRowHidden(row, hide)


class IntezerResultsWidget(QtWidgets.QWidget):
    def __init__(self, bv, block_map, analysis_url, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Intezer Analyze — Results')
        self.resize(1100, 650)

        layout = QtWidgets.QVBoxLayout(self)

        # URL bar
        url_layout = QtWidgets.QHBoxLayout()
        url_label = QtWidgets.QLabel('Analysis URL:')
        url_edit = QtWidgets.QLineEdit(analysis_url)
        url_edit.setReadOnly(True)
        open_btn = QtWidgets.QPushButton('Open in browser')
        open_btn.clicked.connect(lambda: QtGui.QDesktopServices.openUrl(
            QtCore.QUrl(analysis_url)
        ))
        url_layout.addWidget(url_label)
        url_layout.addWidget(url_edit)
        url_layout.addWidget(open_btn)
        layout.addLayout(url_layout)

        # Filter bar
        filter_layout = QtWidgets.QHBoxLayout()
        filter_label = QtWidgets.QLabel('Filter:')
        self._filter_edit = QtWidgets.QLineEdit()
        self._filter_edit.setPlaceholderText('Type to filter rows…')
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self._filter_edit)
        layout.addLayout(filter_layout)

        # Tabs: Blocks | Genes
        self._tabs = QtWidgets.QTabWidget()
        self._block_table = IntezerBlockTable(bv, block_map, self)
        self._gene_table = IntezerGeneTable(bv, block_map, self)
        self._tabs.addTab(self._block_table, 'Blocks ({})'.format(len(block_map)))
        gene_rows = self._gene_table.rowCount()
        self._tabs.addTab(self._gene_table, 'Genes ({})'.format(gene_rows))
        layout.addWidget(self._tabs)

        self._filter_edit.textChanged.connect(self._on_filter)
        self._tabs.currentChanged.connect(lambda _: self._on_filter(self._filter_edit.text()))

        # Ctrl+F focuses filter (QShortcut lives in QtGui in PySide6)
        QtGui.QShortcut(QtGui.QKeySequence('Ctrl+F'), self, self._filter_edit.setFocus)

    def _on_filter(self, text):
        current = self._tabs.currentWidget()
        if hasattr(current, 'filter'):
            current.filter(text)

    def show_panel(self):
        self.setAttribute(QtCore.Qt.WA_DeleteOnClose)
        self.show()
        self.raise_()
