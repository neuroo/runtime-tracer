"""
    Dynamic tracing and IDA integration
    by Romain Gaucher <r@rgaucher.info> - http://rgaucher.info

    Copyright (c) 2011 Romain Gaucher <r@rgaucher.info>

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
"""
import idc
import idaapi
import idautils
import sqlite3
from idaapi import PluginForm
from PySide import QtGui, QtCore
from PySide.QtCore import *
from PySide.QtGui import *


CSS_TREEVIEW = """ QTreeView {
     show-decoration-selected: 1;
 }
 QTreeView::item {
      border: 1px solid #d9d9d9;
     border-top-color: transparent;
     border-bottom-color: transparent;
 }
 QTreeView::item:hover {
     background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: 0 #e7effd, stop: 1 #cbdaf1);
     border: 1px solid #bfcde4;
 }
 QTreeView::item:selected {
     border: 1px solid #567dbc;
 }
 QTreeView::item:selected:active{
     background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: 0 #6ea1f1, stop: 1 #567dbc);
 }
 QTreeView::item:selected:!active {
     background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: 0 #6b9be8, stop: 1 #577fbf);
 }"""


pinIDAPlugin = None

def make_address(integer):
    return "0x%s" % ("%x" % integer).upper()

"""
class PinIDAPluginUIHook(UI_Hooks):
    def __init__(self):
        UI_Hooks.__init__(self)
        self.cmd = None
    
    def get_ea_hint(self, ea):
        print "UI_hook: ea hint:", ea

    def preprocess(self, name):
        self.cmd = name
        print "Received command: %s" % name
        return 0
    
    def postprocess(self):
        print "Postprocessing of ... %s" % self.cmd
        return 0

class PinIDAPluginDelegate(simplecustviewer_t):
    def __init__(self, parent):
        simplecustviewer_t.__init__(self)
        self.__this = _idaapi.pyscv_init(self, "")
        self.parent = parent

    def jumpto(self, address, x=0, y=0):
        print "[PinIDAPluginDelegate] %d" % address
        print "[PinIDAPluginDelegate] here: ", here()
        print "[PinIDAPluginDelegate] ScreenEA: ", ScreenEA()
        return idaapi.jumpto(address)

    def OnCursorPosChanged(self):
        print "PinIDAPluginDelegate::OnCursorPosChanged- ", ScreenEA()
"""

class SearchWidget(QWidget):
    def __init__(self, db, parent=None):
        QWidget.__init__(self, parent)
        self.db = db
        # keyword -> list of addresses, etc.
        self.results = {}
        self.selected_keyword = None

        self.keywords = QTreeWidget(parent)
        self.keywords.setRootIsDecorated(False)
        self.keywords.setColumnCount(1)
        self.keywords.setHeaderLabels(["Keywords"])
        self.keywords.setUniformRowHeights(True)
        self.keywords.setEnabled(True)
        self.keywords.setAlternatingRowColors(True)
        self.keywords.setStyleSheet(CSS_TREEVIEW)
        QObject.connect(self.keywords, SIGNAL('itemClicked(QTreeWidgetItem *, int)'), self.selectKeyword_Slot)

        self.data = QTreeWidget(parent)
        self.data.setRootIsDecorated(False)
        self.data.setColumnCount(3)
        self.data.setHeaderLabels(["Address", "Register", "Address (dec)"])
        self.data.setUniformRowHeights(True)
        self.data.setEnabled(True)
        self.data.setAlternatingRowColors(True)
        self.data.setStyleSheet(CSS_TREEVIEW)
        QObject.connect(self.data, SIGNAL('itemClicked(QTreeWidgetItem *, int)'), self.selectAddress_Slot)

        layout = QHBoxLayout()
        layout.addWidget(self.keywords)
        layout.addWidget(self.data)

        self.setLayout(layout)

    def updateResults(self, keyword, d):
        if keyword is not None and len(keyword) > 1 and keyword not in self.results:            
            self.populateKeywords(keyword)
            self.results.update(d)
        self.populateData(keyword)

    def populateData(self, keyword):

        if keyword not in self.results:
            print "Error!! %s not in %s" % (keyword, self.results.keys())
            return

        self.data.setUpdatesEnabled(False)
        self.data.clear()
        root = self.data.invisibleRootItem()

        for r in self.results[keyword]:
            citem = QTreeWidgetItem()
            citem.setText(0, make_address(r['address']))
            citem.setText(1, r['registers'])
            citem.setText(2, str(r['address']))
            citem.setFlags(citem.flags() | Qt.ItemIsEditable)
            root.addChild(citem)

        self.data.setUpdatesEnabled(True)
        self.data.update()


    def populateKeywords(self, keyword):
        if keyword not in self.results:
            self.results[keyword] = []

        self.keywords.setUpdatesEnabled(False)
        root = self.keywords.invisibleRootItem()

        citem = QTreeWidgetItem()
        citem.setText(0, keyword)
        citem.setFlags(citem.flags() | Qt.ItemIsEditable)
        root.addChild(citem)
        self.keywords.setUpdatesEnabled(True)
        self.keywords.update()

    def selectKeyword_Slot(self, item, column=0):
        self.selected_keyword = item.data(0, Qt.DisplayRole)
        self.populateData(self.selected_keyword)


    def selectAddress_Slot(self, item, column=0):
        selected_address = int(item.data(2, Qt.DisplayRole))
        self.emit(SIGNAL('selectedSearchInstance'), selected_address)


class DetailWidget(QWidget):
    def __init__(self, db, parent=None):
        QWidget.__init__(self, parent)
        self.db = db
        self.selected_trace = 0

        self.data = {}
        self.headers = ["Register", "Content"]

        self.register_list = QTreeWidget(parent)
        self.register_list.setRootIsDecorated(False)
        self.register_list.setColumnCount(2)
        self.register_list.setHeaderLabels(self.headers)
        self.register_list.setUniformRowHeights(True)
        self.register_list.setEnabled(True)
        self.register_list.setAlternatingRowColors(True)
        self.register_list.setStyleSheet(CSS_TREEVIEW)

        QObject.connect(self.register_list, SIGNAL('itemClicked(QTreeWidgetItem *, int)'), self.changeText_Slot)

        self.text_content = QTextEdit(self)
        self.text_content.setStyleSheet("QTextEdit {background-color: #efefef; font-family: consolas,sans-sherif; font-size: 10px;}")

        self.search_label = QLabel("Memory search:")
        self.search_box = QLineEdit()
        self.search_go = QPushButton("Search")
        QObject.connect(self.search_box, SIGNAL('editingFinished()'), self.searchRequested_Slot)
        QObject.connect(self.search_box, SIGNAL('returnPressed()'), self.searchRequested_Slot)
        QObject.connect(self.search_go, SIGNAL('pressed()'), self.searchRequested_Slot)


        self.db_path = QLineEdit(self)
        self.select_file = QPushButton('Open Pin Trace...', self)
        self.select_file.clicked.connect(self.showSelectDBDialog_Slot)

        layout = QHBoxLayout()
        layout.addWidget(self.register_list)
        layout.addWidget(self.text_content)

        hlayout = QHBoxLayout()
        hlayout.addWidget(self.search_label)
        hlayout.addWidget(self.search_box)
        hlayout.addWidget(self.search_go)
        hlayout.addWidget(self.db_path)
        hlayout.addWidget(self.select_file)

        #
        vlayout = QVBoxLayout()
        vlayout.addLayout(hlayout)
        vlayout.addLayout(layout)
         
        self.setLayout(vlayout)

    def showSelectDBDialog_Slot(self):
        fname, ext = QFileDialog.getOpenFileName(self, 'Open Pin Trace File', './', "SQLite DB (*.db)")
        self.emit(SIGNAL("databaseFileNameSelected"), fname)
        self.db_path.setText(fname)

    # s.trace_id, r.name, s.value, s.memory
    def updateRegisterData(self, incoming_data):
        # Update our model
        self.data.clear()
        for e in incoming_data:
            trace_id = int(e[0])
            if trace_id not in self.data:
                self.data[trace_id] = {}
            reg = str(e[1])
            if reg not in self.data[trace_id]:
                self.data[trace_id][reg] = (e[2], e[3])

        traces = self.data.keys()
        traces.sort()
        if len(traces) > 0:
            self.selected_trace = traces[0]
            self.updateTraceView(self.selected_trace)
        self.register_list.update()

    def updateTraceView(self, selected_trace):
        d = self.data[selected_trace]

        self.register_list.setUpdatesEnabled(False)
        self.register_list.clear()
        root = self.register_list.invisibleRootItem()

        for r in d:
            citem = QTreeWidgetItem()
            citem.setText(0, str(r))
            citem.setText(1, hex(d[r][0]))
            citem.setFlags(citem.flags() | Qt.ItemIsEditable)
            root.addChild(citem)
        self.register_list.setUpdatesEnabled(True)
        self.register_list.update()

    def searchRequested_Slot(self):
        text = self.search_box.text()
        if len(text) < 2:
            return
        self.emit(SIGNAL('searchRequested'), text)

    def changeText_Slot(self, item, column):
        selected_register = item.data(0, Qt.DisplayRole)
        if self.selected_trace in self.data:
            self.text_content.setText(str(DetailWidget.hexdump(self.data[self.selected_trace][selected_register][1])))

    @staticmethod
    def hexdump(src, length=8):
        result = []
        digits = 4 if isinstance(src, unicode) else 2
        for i in xrange(0, len(src), length):
            s = src[i:i+length]
            hexa = ' '.join(["%0*X" % (digits, ord(x))  for x in s])
            text = ''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
            result.append("%04X   %-*s   %s" % (i, length * (digits + 1), hexa, text))
        return '\n'.join(result)


ADDRESS_WINDOW = 1024

class PinIDAPlugin(PluginForm):
    def __init__(self):
        PluginForm.__init__(self)
        self.current_position = ScreenEA()
        #self.delegate = PinIDAPluginDelegate(self)
        #self.hook = PinIDAPluginUIHook()
        #self.hook.hook()
        self.detail = None
        self.model = None
        self.timer = None
        self.label = None
        self.headers =  ["Address", "Trace ID", "Disassembly", "Address (dec)"]

        self.db = None

    def updateModel(self):
        if self.db:
            # Query the DB to get data around the current address
            c = self.db.cursor()
            query = 'select i.address, i.trace_id, d.asm from instr i, disasm d where i.address > %d and i.address < %d and i.address = d.address and i.trace_id=1 order by i.address ASC' % (self.current_position - ADDRESS_WINDOW, self.current_position + ADDRESS_WINDOW)
            c.execute(query)
            self.model.removeRows(0, self.model.rowCount())
            for r in c:
                elmModelItem = []
                elmModelItem.append(QStandardItem(make_address(r[0])))
                elmModelItem.append(QStandardItem(str(r[1])))
                elmModelItem.append(QStandardItem(r[2]))
                elmModelItem.append(QStandardItem(str(r[0])))
                self.model.appendRow(elmModelItem)

            # If we are on the current line, highlight it in our view
            self.selectRow(self.current_position)

    def populateDetailedView(self):
        c = self.db.cursor()
        c.execute('select s.trace_id, r.name, s.value, s.memory from snapshot s, register r where r.register = s.register and s.address = %d and s.trace_id=1 order by r.name ASC' % self.current_position)
        data = []
        for r in c:
            data.append([r[0], r[1], r[2], r[3]])
        self.detail.updateRegisterData(data)


    def selectRow(self, pos):
        self.selectionModel.clearSelection()
        to_select = self.model.findItems(str(pos), Qt.MatchRecursive, 3)
        for item in to_select:
            self.selectionModel.select(item.index(), QItemSelectionModel.Select | QItemSelectionModel.Rows)
        self.populateDetailedView()


    def OnCreate(self, form):
        self.parent = self.FormToPySideWidget(form)

        # Create display of registers
        self.label = QLabel("info to go here...")

        self.detail = DetailWidget(self.db, self.parent)
        QObject.connect(self.detail, SIGNAL('databaseFileNameSelected'), self.setSelectedDatabase_Slot)
        QObject.connect(self.detail, SIGNAL('searchRequested'), self.searchSnapshots_Slot)

        self.search = SearchWidget(self.db, self.parent)
        QObject.connect(self.search, SIGNAL('selectedSearchInstance'), self.searchClickedIndex_Slot)

        # Create list
        self.model = QStandardItemModel(0, len(self.headers), self.parent)
        for i in range(len(self.headers)):
            self.model.setHorizontalHeaderItem(i, QStandardItem(self.headers[i]))

        self.root_item = self.model.invisibleRootItem()
        self.current_selection = []
        self.selectionModel = QItemSelectionModel(self.model)
        # QObject.connect(self.selectionModel, SIGNAL('selectionChanged(const QItemSelection&, const QItemSelection&)'), self.selectionChanged_Slot)

        self.proxyModel = QSortFilterProxyModel()
        self.proxyModel.setSourceModel(self.model)

        self.treeview = QTreeView(self.parent)
        self.treeview.setRootIsDecorated(False)
        self.treeview.setAlternatingRowColors(True)
        self.treeview.setSortingEnabled(False)
        self.treeview.setModel(self.model)
        self.treeview.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.treeview.setSelectionModel(self.selectionModel)
        self.treeview.setUniformRowHeights(True)
        self.treeview.setStyleSheet(CSS_TREEVIEW)

        QObject.connect(self.treeview, SIGNAL("clicked(const QModelIndex&)"), self.clickedIndex_Slot)


        self.tabWidget = QTabWidget(self.parent)
        self.tabWidget.setTabPosition(QTabWidget.South) 
        self.tabWidget.addTab(self.treeview, "Nearby Trace Points")
        self.tabWidget.addTab(self.search, "Search Results")

        # Create layout
        layout = QVBoxLayout()
        layout.addWidget(self.detail)
        layout.addWidget(self.tabWidget)
        self.parent.setLayout(layout)

        # Query the DB and populate the list
        self.updateModel()
        self.timer = idaapi.register_timer(200, self.refresh)


    @staticmethod
    def load_sqlite(fname):
        from_file = sqlite3.connect(fname)
        return from_file
        """
        with open('dump.sql', 'w') as f:
            for line in from_file.iterdump():
                f.write('%s\n' % line)

        db = sqlite3.connect(":memory:")
        db.executescript(open('dump.sql').read())

        return db
        """

    def setSelectedDatabase_Slot(self, fname):
        # Load the DB in RAM for faster processing
        self.db = PinIDAPlugin.load_sqlite(fname)
        #
        # self.db = sqlite3.connect(fname)
        self.updateModel()

    def searchSnapshots_Slot(self, text):
        if self.db:
            print "Search for:", text
            # Query the DB to get data around the current address
            c = self.db.cursor()
            query = "select distinct s.address, r.name from snapshot s, register r where r.register = s.register and s.memory LIKE '%%%s%%' order by s.address ASC" % text

            c.execute(query)

            l = {}
            for r in c:
                if text not in l:
                    l[text] = []
                l[text].append({ 'address': r[0], 'registers': r[1] })
            self.search.updateResults(text, l)
            self.tabWidget.setCurrentIndex(1)

    def clickedParent_Slot(self):
        print "Parent clicked:", ScreenEA()

    def selectionChanged_Slot(self, selected, deselected):
        print "Selected items: ", str(selected)


    def clickedIndex_Slot(self, index):
        value = int(self.model.item(index.row(), 3).text())
        self.searchClickedIndex_Slot(value)

    def searchClickedIndex_Slot(self, value, local_comment_data=None):
        a = idaapi.jumpto(value)
        # Highlight the current line in IDA views
        idc.SetColor(value, idc.CIC_ITEM, 0x90EE90)
        if local_comment_data:
            # Add the flow-max information (e.g, call hit 42 times)
            idaapi.add_long_cmt(value, 1, local_comment_data)
        self.selectRow(value)

    def OnClose(self, form):
        pass

    def Show(self):
        return PluginForm.Show(self, "Pin Trace Information", options=PluginForm.FORM_PERSIST)

    def updatePosition(self, new_position):
        self.current_position = new_position
        self.updateModel()

    def refresh(self):
        ea = ScreenEA()
        if not (ea == self.current_position):
            # Make sure to reset the color code in IDA
            if self.current_position > 0:
                idc.SetColor(self.current_position, idc.CIC_ITEM, 0xFFFFFFFF)
            self.updatePosition(ea)
        return 200


def main():
    global pinIDAPlugin
    pinIDAPlugin = PinIDAPlugin()
    pinIDAPlugin.Show()

main()