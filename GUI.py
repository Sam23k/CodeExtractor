import sys
import os
import subprocess
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QTextEdit, QSplitter, QTreeWidget, QTreeWidgetItem, 
                             QFrame, QProgressBar, QMenu, QAction, QTabWidget, 
                             QTableWidget, QTableWidgetItem, QHeaderView)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QIcon, QPixmap, QBrush

from Config import STYLES, ICON_PATH
from Threading import DecompilerThread

class PentestGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VU CodeShield v1.3")
        self.resize(1200, 800)
        self.setAcceptDrops(True)
        if os.path.exists(ICON_PATH): self.setWindowIcon(QIcon(ICON_PATH))
        self.initUI()

    def initUI(self):
        self.setStyleSheet(STYLES)
        w = QWidget(); self.setCentralWidget(w); l = QVBoxLayout(); w.setLayout(l); l.setContentsMargins(0,0,0,0)
        
        # Header
        h = QFrame(); h.setObjectName("Header"); h.setFixedHeight(80)
        hl = QHBoxLayout(); hl.setContentsMargins(20, 10, 20, 10)
        
        v = QVBoxLayout(); t = QLabel("VU CodeShield"); t.setObjectName("Title"); v.addWidget(t)
        s = QLabel("VAPT SUITE"); s.setObjectName("Subtitle"); v.addWidget(s)
        hl.addLayout(v); hl.addStretch()
        
        self.pill = QLabel(" READY "); 
        self.pill.setStyleSheet("border: 2px solid #C0392B; color: #C0392B; border-radius: 4px; padding: 6px 12px; font-weight: bold;")
        hl.addWidget(self.pill)
        h.setLayout(hl); l.addWidget(h)
        
        # Tabs
        self.tabs = QTabWidget()
        tab1 = QWidget(); t1 = QHBoxLayout(); tab1.setLayout(t1)
        self.log = QTextEdit(); self.log.setReadOnly(True)
        self.tree = QTreeWidget(); self.tree.setHeaderLabels(["File Name", "Type"]); self.tree.setColumnWidth(0, 400)
        self.tree.itemDoubleClicked.connect(self.open_item)
        
        spl = QSplitter(Qt.Horizontal); spl.addWidget(self.log); spl.addWidget(self.tree); spl.setSizes([300, 900])
        t1.addWidget(spl)
        
        tab2 = QWidget(); t2 = QVBoxLayout(); tab2.setLayout(t2)
        self.vuln_table = QTableWidget(); self.vuln_table.setColumnCount(4)
        self.vuln_table.setHorizontalHeaderLabels(["SEVERITY", "VULNERABILITY", "FILE", "MATCH DETAILS"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        t2.addWidget(self.vuln_table)
        
        self.tabs.addTab(tab1, "📂 SOURCE FILES"); self.tabs.addTab(tab2, "🛡️ VAPT FINDINGS")
        l.addWidget(self.tabs)
        
        self.prog = QProgressBar(); self.prog.setTextVisible(False); self.prog.setRange(0, 100)
        l.addWidget(self.prog)

    def dragEnterEvent(self, e): e.accept()
    def dropEvent(self, e): self.start([u.toLocalFile() for u in e.mimeData().urls()][0])
    
    def start(self, path):
        self.log.clear(); self.tree.clear(); self.vuln_table.setRowCount(0)
        self.prog.setValue(0); self.pill.setText(" PROCESSING ")
        
        self.th = DecompilerThread(path)
        self.th.log_signal.connect(self.log.append)
        self.th.status_signal.connect(self.pill.setText)
        self.th.progress_signal.connect(self.prog.setValue)
        self.th.pulse_signal.connect(self.toggle_pulse)
        self.th.finished_signal.connect(self.done)
        self.th.start()

    def toggle_pulse(self, active):
        if active: self.prog.setRange(0, 0)
        else: self.prog.setRange(0, 100)

    def done(self, path, findings):
        self.prog.setRange(0, 100); self.prog.setValue(100)
        self.pill.setText(" COMPLETE ")
        self.populate_tree(path)
        self.populate_vulns(findings)
        if findings: self.tabs.setCurrentIndex(1)
        # Auto-open Report
        # report_path = os.path.join(os.path.dirname(path), "VULNERABILITY_REPORT.html")
        # if os.path.exists(report_path): os.startfile(report_path)

    def populate_tree(self, path):
        root = QTreeWidgetItem(self.tree); root.setText(0, os.path.basename(path)); root.setExpanded(True)
        self.add_rec(root, path)

    def add_rec(self, p, path):
        try:
            for e in os.scandir(path):
                if e.name.endswith(('.dll','.png','.ico')): continue
                i = QTreeWidgetItem(p); i.setText(0, e.name); i.setData(0, Qt.UserRole, e.path)
                if e.is_dir(): self.add_rec(i, e.path)
        except: pass

    def populate_vulns(self, findings):
        self.vuln_table.setRowCount(len(findings))
        for r, f in enumerate(findings):
            sev = QTableWidgetItem(f['severity']); sev.setTextAlignment(Qt.AlignCenter)
            if f['severity'] == "CRITICAL": sev.setBackground(QBrush(QColor("#C0392B"))); sev.setForeground(QBrush(QColor("white")))
            elif f['severity'] == "HIGH": sev.setBackground(QBrush(QColor("#E67E22"))); sev.setForeground(QBrush(QColor("white")))
            else: sev.setBackground(QBrush(QColor("#F1C40F")))
            self.vuln_table.setItem(r, 0, sev)
            self.vuln_table.setItem(r, 1, QTableWidgetItem(f['name']))
            self.vuln_table.setItem(r, 2, QTableWidgetItem(f['file']))
            self.vuln_table.setItem(r, 3, QTableWidgetItem(f['matches']))

    def open_item(self, i): 
        p = i.data(0, Qt.UserRole)
        # SECURITY FIX: Force open in Notepad/Text Editor instead of executing
        if p and os.path.exists(p) and not os.path.isdir(p):
            if os.name == 'nt':
                subprocess.Popen(["notepad.exe", p])
            else:
                subprocess.Popen(["xdg-open", p])