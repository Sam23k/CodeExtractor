# import sys
# import subprocess
# import os
# import re

# # CONFIG
# TOOL_PYCDAS = "/home/sam/Desktop/RE_Arsenal/Tools/pycdc/pycdas"

# def clean_disassembly(raw_text):
#     """
#     Cleans up raw pycdas output to make it token-efficient for LLMs.
#     Removes memory addresses and hex dumps, keeping only the logic.
#     """
#     clean_lines = []
    
#     # Python 3.13 Opcode Regex (approximate structure)
#     # Looks for:  105 LOAD_FAST                0: self
#     code_pattern = re.compile(r"^\s*\d+\s+([A-Z_]+)\s+(.*)")
    
#     for line in raw_text.splitlines():
#         # Keep nicely formatted header info
#         if "Python" in line or "File:" in line:
#             clean_lines.append(f"# {line.strip()}")
#             continue
            
#         # Parse Instructions
#         match = code_pattern.search(line)
#         if match:
#             opcode = match.group(1)
#             arg = match.group(2).strip()
#             # formatting for AI readability
#             clean_lines.append(f"{opcode:<20} {arg}")
            
#     return "\n".join(clean_lines)

# def generate_prompt(filepath):
#     if not os.path.exists(filepath):
#         print("File not found.")
#         return

#     # 1. Run Disassembler (pycdas) - It rarely fails, unlike pycdc
#     try:
#         result = subprocess.run(
#             [TOOL_PYCDAS, filepath], 
#             capture_output=True, 
#             text=True
#         )
#         raw_asm = result.stdout
#     except Exception as e:
#         print(f"Disassembly failed: {e}")
#         return

#     # 2. Clean it
#     cleaned_asm = clean_disassembly(raw_asm)

#     # 3. Create the LLM Prompt
#     prompt = f"""
# I have a Python 3.13 Bytecode Disassembly that standard decompilers cannot handle.
# Please reconstruct the original Python Source Code from this disassembly.
# Focus on the logic flow, class structures, and method calls.

# --- START DISASSEMBLY ---
# {cleaned_asm}
# --- END DISASSEMBLY ---

# Output only the Python code.
#     """
    
#     # 4. Save or Print
#     output_file = filepath + ".prompt.txt"
#     with open(output_file, "w") as f:
#         f.write(prompt)
    
#     print(f"\n[+] AI Prompt Generated: {output_file}")
#     print(f"[+] Size: {len(prompt)} chars")
#     print("-" * 40)
#     print("INSTRUCTIONS:")
#     print("1. Open the file above.")
#     print("2. Copy the text.")
#     print("3. Paste into ChatGPT-4 or Claude 3.")
#     print("4. Paste the result back into your source file.")

# if __name__ == "__main__":
#     if len(sys.argv) < 2:
#         print("Usage: python3 ai_bridge.py <target.pyc>")
#     else:
#         generate_prompt(sys.argv[1])





































import sys
import os
import shutil
import subprocess
import multiprocessing
import concurrent.futures
import dis
import marshal
import time
import struct
import io
from contextlib import redirect_stdout
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QPushButton, QTextEdit, QFileDialog, QProgressBar, QMessageBox, QFrame,
                             QSplitter, QTreeWidget, QTreeWidgetItem, QHeaderView, QMenu, QAction)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl, QTimer
from PyQt5.QtGui import QDragEnterEvent, QDropEvent, QFont, QColor, QPalette

# ==============================================================================
#  CONFIGURATION (WINDOWS OPTIMIZED)
# ==============================================================================
ARSENAL_BASE = r"C:\Users\PC\Desktop\RE_Arsenal"
WORKSPACE_DIR = os.path.join(ARSENAL_BASE, "Workspace")

# Tools
TOOL_EXTRACTOR = os.path.join(ARSENAL_BASE, r"Tools\pyinstxtractor\pyinstxtractor.py")
TOOL_JADX = os.path.join(ARSENAL_BASE, r"Tools\jadx\bin\jadx.bat")
JAVA_RAM = "-Xmx4g"
TOOL_PYCDC = "MISSING" # We will skip the C++ decompile and use AI Bridge instead

# ==============================================================================
#  BACKEND THREAD (EXTRACTOR)
# ==============================================================================
class DecompilerThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(str)

    def __init__(self, input_file):
        super().__init__()
        self.original_input = input_file

    def log(self, msg):
        self.log_signal.emit(f"[*] {msg}")

    def run(self):
        self.log(f"Processing: {os.path.basename(self.original_input)}")
        
        # 1. Prepare Workspace
        filename = os.path.basename(self.original_input)
        clean_name = os.path.splitext(filename)[0].replace(" ", "_")
        case_dir = os.path.join(WORKSPACE_DIR, f"Case_{int(time.time())}_{clean_name}")
        evidence_dir = os.path.join(case_dir, "Evidence")
        source_dir = os.path.join(case_dir, "Recovered_Source")
        
        os.makedirs(evidence_dir, exist_ok=True)
        os.makedirs(source_dir, exist_ok=True)
        
        # 2. Determine Type & Extract
        if filename.lower().endswith(('.jar', '.war')):
            self.run_java(self.original_input, source_dir)
        else:
            self.run_python(self.original_input, source_dir)
            
        self.finished_signal.emit(source_dir)

    def run_java(self, filepath, out_dir):
        self.log("Detected JAVA. Running JADX...")
        if not os.path.exists(TOOL_JADX):
            self.log("ERROR: JADX not found. Please install it.")
            return
        subprocess.run([TOOL_JADX, "-d", out_dir, "-j", "4", filepath], 
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.log("Java Decompilation Complete.")

    def run_python(self, filepath, out_dir):
        self.log("Detected PYTHON (PyInstaller). Extracting...")
        
        # Copy to evidence to avoid messing up original
        target_copy = os.path.join(out_dir, os.path.basename(filepath))
        shutil.copy2(filepath, target_copy)
        
        # Run Extractor
        cmd = [sys.executable, TOOL_EXTRACTOR, target_copy]
        subprocess.run(cmd, cwd=out_dir, stdout=subprocess.DEVNULL)
        
        # Cleanup
        if os.path.exists(target_copy): os.remove(target_copy)
        
        self.log("Extraction Complete. Browse files to generate AI Prompts.")

# ==============================================================================
#  UPDATED AI BRIDGE LOGIC
# ==============================================================================
def get_native_disassembly(pyc_path):
    """
    Robust disassembly that tries multiple offsets to find valid bytecode.
    """
    try:
        with open(pyc_path, 'rb') as f:
            data = f.read()
        
        code_obj = None
        error_log = []

        # ATTEMPT 1: Raw Marshal (Offset 0) - Common for PYZ extracted files
        try:
            code_obj = marshal.loads(data)
        except Exception as e:
            error_log.append(f"Offset 0 failed: {e}")

        # ATTEMPT 2: Standard .pyc Header (Offset 16) - Python 3.7+
        if not code_obj and len(data) > 16:
            try:
                code_obj = marshal.loads(data[16:])
            except Exception as e:
                error_log.append(f"Offset 16 failed: {e}")

        # ATTEMPT 3: Old Header (Offset 8 or 12)
        if not code_obj and len(data) > 12:
            try:
                code_obj = marshal.loads(data[12:]) # Python 3.3-3.6
            except:
                try:
                    code_obj = marshal.loads(data[8:]) # Python 2.7ish
                except Exception as e:
                    error_log.append(f"Offset 8/12 failed: {e}")

        if not code_obj:
            return f"ERROR: Could not read bytecode.\nDebug info:\n" + "\n".join(error_log) + "\n\nCRITICAL TIP: Your target uses Python 3.12. Ensure YOU are running this script with Python 3.12."
            
        # Capture the disassembly output
        f_out = io.StringIO()
        with redirect_stdout(f_out):
            dis.dis(code_obj)
        return f_out.getvalue()

    except Exception as e:
        return f"ERROR: System failure: {str(e)}"

# ==============================================================================
#  FRONTEND GUI
# ==============================================================================
class DecompilerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Arsenal Decompiler v3 - AI Enabled")
        self.setGeometry(100, 100, 1200, 750)
        self.setAcceptDrops(True)
        self.initUI()
        self.worker = None

    def initUI(self):
        # Dark Theme
        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #1e1e1e; color: #d4d4d4; font-family: 'Segoe UI'; }
            QTreeWidget { background-color: #252526; border: 1px solid #3e3e42; }
            QTextEdit { background-color: #1e1e1e; font-family: 'Consolas'; border: 1px solid #3e3e42; }
            QHeaderView::section { background-color: #2d2d30; padding: 5px; border: none; }
            QPushButton { background-color: #0e639c; color: white; border: none; padding: 8px; }
            QPushButton:hover { background-color: #1177bb; }
            QPushButton:disabled { background-color: #333; color: #666; }
        """)

        layout = QVBoxLayout()
        
        # Header
        header = QLabel("Arsenal Decompiler")
        header.setFont(QFont("Segoe UI", 16, QFont.Bold))
        layout.addWidget(header)

        # Splitter
        splitter = QSplitter(Qt.Horizontal)
        
        # LOGS (Left)
        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        splitter.addWidget(self.logs)

        # FILE TREE (Right)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["File Name", "Type"])
        self.tree.setColumnWidth(0, 300)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.open_menu)
        self.tree.itemDoubleClicked.connect(self.handle_double_click)
        splitter.addWidget(self.tree)
        
        splitter.setSizes([400, 800])
        layout.addWidget(splitter)

        # Status
        self.status = QLabel("Ready - Drop Target Here")
        self.status.setStyleSheet("color: #0e639c; font-weight: bold;")
        layout.addWidget(self.status)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    # --- DRAG & DROP ---
    def dragEnterEvent(self, e): e.accept()
    def dropEvent(self, e):
        files = [u.toLocalFile() for u in e.mimeData().urls()]
        if files: self.start_analysis(files[0])

    def start_analysis(self, path):
        self.logs.clear()
        self.tree.clear()
        self.logs.append(f"Analyzing: {path}")
        self.worker = DecompilerThread(path)
        self.worker.log_signal.connect(self.logs.append)
        self.worker.finished_signal.connect(self.analysis_done)
        self.worker.start()

    def analysis_done(self, path):
        self.status.setText("Analysis Complete")
        self.populate_tree(path)
        QMessageBox.information(self, "Done", f"Files extracted to:\n{path}")

    # --- TREE VIEW ---
    def populate_tree(self, path):
        root = QTreeWidgetItem(self.tree)
        root.setText(0, os.path.basename(path))
        root.setData(0, Qt.UserRole, path)
        self.add_items(root, path)
        root.setExpanded(True)

    def add_items(self, parent, path):
        try:
            for entry in os.scandir(path):
                item = QTreeWidgetItem(parent)
                item.setText(0, entry.name)
                item.setData(0, Qt.UserRole, entry.path)
                if entry.is_dir():
                    item.setText(1, "DIR")
                    self.add_items(item, entry.path)
                else:
                    ext = os.path.splitext(entry.name)[1].upper()
                    item.setText(1, ext if ext else "FILE")
        except: pass

    # --- AI BRIDGE CONTEXT MENU ---
    def open_menu(self, position):
        item = self.tree.itemAt(position)
        if not item: return
        
        filepath = item.data(0, Qt.UserRole)
        if filepath.endswith(".pyc"):
            menu = QMenu()
            action = QAction("🤖 Generate AI Decompile Prompt", self)
            action.triggered.connect(lambda: self.generate_prompt(filepath))
            menu.addAction(action)
            menu.exec_(self.tree.viewport().mapToGlobal(position))

    def generate_prompt(self, filepath):
        self.logs.append(f"\n[AI BRIDGE] Generating prompt for: {os.path.basename(filepath)}...")
        
        # 1. Get Disassembly (Native Python)
        raw_asm = get_native_disassembly(filepath)
        
        # 2. Create Prompt
        prompt = f"""I have a Python Bytecode Disassembly. 
Please reconstruct the original Python Source Code from this. I would like the entire code in the format of a source code
Focus on logic flow, class structures, and method calls. Also, if I add more Bitcode Disassembly - Please relate each of them
with each other and build the logic of the application completely.

--- START DISASSEMBLY ---
{raw_asm[:15000]} 
--- END DISASSEMBLY ---
(Truncated to 15k chars for token limits if necessary)
"""
        # 3. Save to file
        out_file = filepath + ".AI_PROMPT.txt"
        with open(out_file, "w", encoding='utf-8') as f:
            f.write(prompt)
            
        self.logs.append(f"[SUCCESS] Prompt saved: {out_file}")
        
        # 4. Open it automatically
        os.startfile(out_file)

    def handle_double_click(self, item):
        path = item.data(0, Qt.UserRole)
        if os.path.exists(path):
            os.startfile(path)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    app = QApplication(sys.argv)
    window = DecompilerGUI()
    window.show()
    sys.exit(app.exec_())