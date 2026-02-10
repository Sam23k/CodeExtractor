#YOU CAN EITHER RUN THE MAIN FILE OR YOU CAN RUN THIS DIRECTLY AS A NOT SPLITTED CODE


# import sys
# import multiprocessing
# from PyQt5.QtWidgets import QApplication
# from GUI import PentestGUI

# if __name__ == "__main__":
#     # Required for pyinstaller/multiprocessing
#     multiprocessing.freeze_support()
    
#     app = QApplication(sys.argv)
#     window = PentestGUI()
#     window.show()
#     sys.exit(app.exec_())







  


























# # import sys
# # import os
# # import shutil
# # import subprocess
# # import multiprocessing
# # import dis
# # import marshal
# # import time
# # import io
# # import types
# # import re
# # import traceback
# # import base64
# # import json
# # from datetime import datetime
# # from contextlib import redirect_stdout
# # from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
# #                              QLabel, QTextEdit, QSplitter, QTreeWidget, QTreeWidgetItem, 
# #                              QFrame, QProgressBar, QAbstractItemView, QMenu, QAction, 
# #                              QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView)
# # from PyQt5.QtCore import Qt, QThread, pyqtSignal
# # from PyQt5.QtGui import QColor, QIcon, QPixmap, QBrush

# # # ==============================================================================
# # #  CONFIGURATION
# # # ==============================================================================
# # ARSENAL_BASE = r"C:\Users\PC\Desktop\RE_Arsenal"
# # WORKSPACE_DIR = os.path.join(ARSENAL_BASE, "Workspace")
# # LOGO_PATH = r"C:\Users\PC\Desktop\RE_Arsenal\Scripts\Icon\vu_logo_bg.png"

# # # TOOLS
# # TOOL_EXTRACTOR = os.path.join(ARSENAL_BASE, r"Tools\pyinstxtractor\pyinstxtractor.py")
# # TOOL_JADX = os.path.join(ARSENAL_BASE, r"Tools\jadx\bin\jadx.bat")
# # TOOL_PYCDC = os.path.join(ARSENAL_BASE, r"Tools\pycdc\pycdc.exe")
# # TOOL_ILSPY_EXE = os.path.join(ARSENAL_BASE, r"Tools\ilspy\ilspycmd.exe")
# # TOOL_ILSPY_DLL = os.path.join(ARSENAL_BASE, r"Tools\ilspy\ilspycmd.dll")
# # TOOL_GHIDRA_HEADLESS = os.path.join(ARSENAL_BASE, r"Tools\ghidra\support\analyzeHeadless.bat")

# # # ==============================================================================
# # #  VAPT DATABASE
# # # ==============================================================================
# # VULN_DB = [
# #     {"name": "AWS Access Key", "regex": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "severity": "CRITICAL", "desc": "Hardcoded AWS Credential"},
# #     {"name": "Private Key", "regex": r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----", "severity": "CRITICAL", "desc": "Embedded Cryptographic Private Key"},
# #     {"name": "Google API Key", "regex": r"AIza[0-9A-Za-z\\-_]{35}", "severity": "CRITICAL", "desc": "Hardcoded Google Cloud API Key"},
# #     {"name": "Hardcoded Password", "regex": r"(password|passwd|pwd|secret|token|api_key)\s*=\s*['\"][\w@#$%]{5,}['\"]", "severity": "HIGH", "desc": "Possible hardcoded credential"},
# #     {"name": "Command Injection", "regex": r"(os\.system|subprocess\.call|Runtime\.getRuntime\(\)\.exec|system\()", "severity": "HIGH", "desc": "Execution of OS commands"},
# #     {"name": "Unsafe Deserialization", "regex": r"(pickle\.loads|Marshal\.load|ObjectInputStream)", "severity": "HIGH", "desc": "Potential RCE via deserialization"},
# #     {"name": "Weak Hashing (MD5)", "regex": r"(MD5|md5)", "severity": "MEDIUM", "desc": "Use of broken cryptographic algorithm"},
# #     {"name": "Internal IP Address", "regex": r"\b192\.168\.\d{1,3}\.\d{1,3}\b|\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "severity": "MEDIUM", "desc": "Hardcoded Internal IP"},
# # ]

# # # ==============================================================================
# # #  HELPER ENGINES
# # # ==============================================================================
# # class SemanticRenamer:
# #     PATTERNS = [
# #         (r"open\s*\(([^,]+),\s*['\"]r['\"]", "file_path"),
# #         (r"read\s*\(([^)]+)\)", "file_stream"),
# #         (r"socket\.connect\s*\(\s*\(([^,]+),\s*([^)]+)\)\s*\)", "target_host"),
# #         (r"base64\.b64decode\s*\(([^)]+)\)", "encoded_data"),
# #         (r"sqlite3\.connect\s*\(([^)]+)\)", "db_path"),
# #     ]
# #     @staticmethod
# #     def process(code):
# #         renames = {}
# #         for line in code.splitlines():
# #             for pattern, hint in SemanticRenamer.PATTERNS:
# #                 m = re.search(pattern, line)
# #                 if m:
# #                     var = m.group(1).strip()
# #                     if re.match(r"^[a-zA-Z_]\w*$", var) and len(var) < 15: renames[var] = hint
# #         new_code = code
# #         for old, new in renames.items():
# #             new_code = re.sub(r'\b' + re.escape(old) + r'\b', new, new_code)
# #         return new_code

# # class TypeInferencer:
# #     @staticmethod
# #     def process(code):
# #         lines = []
# #         for line in code.splitlines():
# #             line = re.sub(r'(\w+)\s*=\s*\[\]', r'\1: list = []', line)
# #             line = re.sub(r'(\w+)\s*=\s*\{\}', r'\1: dict = {}', line)
# #             line = re.sub(r'(\w+)\s*=\s*(\".*?\"|\'.*?\')', r'\1: str = \2', line)
# #             line = re.sub(r'(\w+)\s*=\s*(\d+)', r'\1: int = \2', line)
# #             lines.append(line)
# #         return "\n".join(lines)

# # class AdvancedSanitizer:
# #     @staticmethod
# #     def clean(source_code):
# #         cleaned = re.sub(r"NULL\s*\|\s*self\s*\+\s*", "self.", source_code)
# #         cleaned = re.sub(r"NULL\s*\+\s*", "", cleaned)
# #         lines = []
# #         for line in cleaned.splitlines():
# #             s = line.strip()
# #             if s == "return": continue
# #             if re.match(r"^(\w+)\s*=\s*\1$", s): continue
# #             if "if 1 == 0:" in s or "if False:" in s: continue
# #             lines.append(line)
# #         return "\n".join(lines)

# # class MagicPatcher:
# #     HEADERS = { "3.12": b'\xcb\x0d\x0d\x0a', "3.11": b'\xa7\x0d\x0d\x0a', "3.10": b'\x6f\x0d\x0d\x0a', "3.9": b'\x61\x0d\x0d\x0a' }
# #     @staticmethod
# #     def try_patch(pyc_path):
# #         try:
# #             with open(pyc_path, "rb") as f: raw = f.read()
# #             if len(raw) < 16: return None
# #         except: return None
# #         for ver, magic in MagicPatcher.HEADERS.items():
# #             tmp = pyc_path + f".{ver}.pyc"
# #             with open(tmp, "wb") as f: f.write(magic + b'\x00'*12 + raw)
# #             try:
# #                 res = subprocess.run([TOOL_PYCDC, tmp], capture_output=True, text=True, timeout=3)
# #                 os.remove(tmp)
# #                 if res.stdout and ("def " in res.stdout or "import " in res.stdout): return res.stdout
# #             except: 
# #                 if os.path.exists(tmp): os.remove(tmp)
# #         return None

# # # ==============================================================================
# # #  PYTHON DECOMPILATION (RECURSIVE EXPANSION)
# # # ==============================================================================
# # class StackDecompilerV2:
# #     def __init__(self, code_obj, indent_level=0):
# #         self.co = code_obj
# #         self.output = []
# #         self.indent_level = indent_level
# #     def indent(self): return "    " * self.indent_level

# #     def decompile(self):
# #         name = self.co.co_name
# #         if name == "__init__":
# #             self.output.insert(0, f"{self.indent()}class RecoveredClass:")
# #             self.indent_level += 1
        
# #         args = ", ".join(self.co.co_varnames[:self.co.co_argcount])
# #         self.output.append(f"{self.indent()}def {name}({args}):")
# #         self.indent_level += 1
        
# #         try:
# #             instructions = list(dis.get_instructions(self.co))
# #             stack = []
# #             for instr in instructions:
# #                 op, arg, repr_val = instr.opname, instr.argval, instr.argrepr
# #                 if "LOAD_CONST" in op: stack.append(repr(arg))
# #                 elif "LOAD_" in op: stack.append(str(repr_val))
# #                 elif "STORE_" in op:
# #                     if stack:
# #                         val = stack.pop()
# #                         if "<code object" not in val: 
# #                             self.output.append(f"{self.indent()}{repr_val} = {val}")
# #                 elif "RETURN_VALUE" in op:
# #                     if stack: self.output.append(f"{self.indent()}return {stack.pop()}")
# #                 elif "CALL" in op:
# #                     count = instr.arg; c_args = []
# #                     for _ in range(count):
# #                         if stack: c_args.insert(0, stack.pop())
# #                     func = stack.pop() if stack else "func"
# #                     stack.append(f"{func}({', '.join(c_args)})")
# #         except: pass

# #         # RECURSIVE EXPANSION
# #         for const in self.co.co_consts:
# #             if isinstance(const, types.CodeType):
# #                 self.output.append("")
# #                 self.output.append(StackDecompilerV2(const, self.indent_level).decompile())
                
# #         return "\n".join(self.output)

# # class OmniscientEngine:
# #     @staticmethod
# #     def generate_full_view(pyc_path, source_code):
# #         code = AdvancedSanitizer.clean(source_code)
# #         code = TypeInferencer.process(code)
# #         code = SemanticRenamer.process(code)
# #         asm = "Bytecode Unavailable"
# #         try:
# #             with open(pyc_path, 'rb') as f: 
# #                 data = f.read()
# #                 code_obj = marshal.loads(data[16:])
# #                 f_out = io.StringIO()
# #                 dis.dis(code_obj, file=f_out) # Capture to string, not terminal
# #                 asm = f_out.getvalue()
# #         except: pass
# #         return f"# FILE: {os.path.basename(pyc_path)}\n# RE-TOOLKIT RECONSTRUCTION:\n{code}\n\n# RAW BYTECODE:\n{asm}"

# # # ==============================================================================
# # #  GHIDRA INTEGRATION (FIXED STREAMING)
# # # ==============================================================================
# # GHIDRA_EXPORT_SCRIPT = """
# # import os
# # from ghidra.app.decompiler import DecompInterface
# # from ghidra.util.task import ConsoleTaskMonitor
# # args = getScriptArgs()
# # if len(args) > 0:
# #     out_dir = args[0]
# #     if not os.path.exists(out_dir): os.makedirs(out_dir)
# #     program = currentProgram; decomplib = DecompInterface(); decomplib.openProgram(program); monitor = ConsoleTaskMonitor()
# #     listing = program.getListing(); iterator = listing.getFunctions(True)
# #     count = 0
# #     print("VU-LOG: Starting Analysis...")
# #     while iterator.hasNext():
# #         func = iterator.next(); count += 1
# #         if count % 20 == 0: print("VU-LOG: Decompiling Function #" + str(count) + " - " + func.getName())
# #         try:
# #             results = decomplib.decompileFunction(func, 5, monitor)
# #             if results.decompileCompleted():
# #                 code = results.getDecompiledFunction().getC()
# #                 fname = func.getName()
# #                 safe = "".join(x for x in fname if x.isalnum() or x in "_")
# #                 if not safe: safe = "UNKNOWN"
# #                 with open(os.path.join(out_dir, safe + ".c"), "w") as f:
# #                     f.write("/* Ghidra: " + func.getName() + " */\\n" + code)
# #         except: pass
# #     print("VU-LOG: Analysis Complete.")
# # """

# # class GhidraEngine:
# #     def __init__(self, log_signal, status_signal):
# #         self.log_signal = log_signal; self.status_signal = status_signal
# #     def run(self, target_path, output_dir):
# #         if not os.path.exists(TOOL_GHIDRA_HEADLESS):
# #             self.log_signal.emit("❌ Ghidra Headless not found."); return
# #         self.log_signal.emit("🚀 Launching GHIDRA C/C++ DECOMPILER...")
# #         self.log_signal.emit("⏳ Streaming logs (Wait for initialization)...")
# #         self.status_signal.emit("GHIDRA RUNNING")
        
# #         script_path = os.path.join(WORKSPACE_DIR, "ghidra_export.py")
# #         with open(script_path, "w") as f: f.write(GHIDRA_EXPORT_SCRIPT)
# #         proj_path = os.path.join(WORKSPACE_DIR, "Ghidra_Proj"); proj_name = f"P_{int(time.time())}"
# #         if not os.path.exists(proj_path): os.makedirs(proj_path)
        
# #         cmd = [TOOL_GHIDRA_HEADLESS, proj_path, proj_name, "-import", target_path, "-postScript", script_path, output_dir, "-deleteProject"]
# #         try:
# #             # FIXED: Popen allows reading stdout line-by-line in real-time
# #             process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
            
# #             for line in process.stdout:
# #                 clean = line.strip()
# #                 # FIXED LOGIC: Show INFO logs so user knows it's loading
# #                 if "VU-LOG" in clean: 
# #                     self.log_signal.emit(f"⚙️ {clean.split('VU-LOG:')[-1].strip()}")
# #                 elif "INFO" in clean or "REPORT" in clean:
# #                     # Strip long paths for cleaner UI
# #                     msg = clean.split("INFO")[-1].split("REPORT")[-1].strip()[:80]
# #                     self.log_signal.emit(f"📝 GHIDRA: {msg}...")
# #                 elif "ERROR" in clean: 
# #                     self.log_signal.emit(f"⚠️ {clean}")
            
# #             process.wait()
# #             self.log_signal.emit("✅ Ghidra Finished.")
# #         except Exception as e: self.log_signal.emit(f"❌ Critical Error: {e}")

# # # ==============================================================================
# # #  VAPT & REPORTING
# # # ==============================================================================
# # class VulnerabilityScanner:
# #     @staticmethod
# #     def scan_file(filepath, content):
# #         findings = []
# #         for sig in VULN_DB:
# #             matches = re.findall(sig['regex'], content, re.IGNORECASE)
# #             if matches:
# #                 unique = list(set(matches))[:5]
# #                 findings.append({ "severity": sig['severity'], "name": sig['name'], "desc": sig['desc'], "file": os.path.basename(filepath), "matches": str(unique), "path": filepath })
# #         return findings

# # class ReportGenerator:
# #     @staticmethod
# #     def generate_html(case_dir, findings):
# #         report_path = os.path.join(case_dir, "VULNERABILITY_REPORT.html")
# #         stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
# #         for f in findings: stats[f['severity']] = stats.get(f['severity'], 0) + 1
        
# #         html = f"""<html><head><title>VU RED TEAM REPORT</title>
# #         <style>body{{font-family:Arial;background:#F5F7FA;padding:20px;}}h1{{color:#C0392B;}}
# #         .summary{{display:flex;gap:20px;margin-bottom:30px;}} .card{{background:white;padding:20px;border-radius:5px;width:200px;text-align:center;box-shadow:0 2px 5px rgba(0,0,0,0.1);}}
# #         .crit{{border-top:5px solid #C0392B;color:#C0392B;font-weight:bold;}} .high{{border-top:5px solid #E67E22;color:#E67E22;font-weight:bold;}}
# #         table{{width:100%;border-collapse:collapse;background:white;}} th,td{{padding:12px;text-align:left;border-bottom:1px solid #ddd;}} th{{background:#2C3E50;color:white;}}
# #         </style></head><body><h1>🛡️ VAPT REPORT</h1><p>Target: {os.path.basename(case_dir)}</p>
# #         <div class="summary"><div class="card crit">CRITICAL<br>{stats['CRITICAL']}</div><div class="card high">HIGH<br>{stats['HIGH']}</div></div>
# #         <table><tr><th>SEVERITY</th><th>ISSUE</th><th>FILE</th><th>EVIDENCE</th></tr>"""
# #         for f in findings: html += f"<tr><td>{f['severity']}</td><td><b>{f['name']}</b></td><td>{f['file']}</td><td><code>{f['matches'][:80]}...</code></td></tr>"
# #         html += "</table></body></html>"
# #         with open(report_path, "w", encoding="utf-8") as f: f.write(html)
# #         return report_path

# # # ==============================================================================
# # #  WORKER THREAD
# # # ==============================================================================
# # class StructureNormalizer:
# #     @staticmethod
# #     def reorganize_csharp(source_root):
# #         for root, dirs, files in os.walk(source_root):
# #             for file in files:
# #                 if not file.endswith(".cs"): continue
# #                 try:
# #                     with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
# #                         for line in f:
# #                             if line.strip().startswith("namespace "):
# #                                 ns = line.strip().split(" ")[1].split(";")[0]
# #                                 tgt = os.path.join(source_root, ns.replace(".", os.sep))
# #                                 if not os.path.exists(tgt): os.makedirs(tgt)
# #                                 shutil.move(os.path.join(root, file), os.path.join(tgt, file)); break
# #                 except: pass

# # class DecompilerThread(QThread):
# #     log_signal = pyqtSignal(str); finished_signal = pyqtSignal(str, list)
# #     status_signal = pyqtSignal(str); progress_signal = pyqtSignal(int)
    
# #     def __init__(self, input_file): 
# #         super().__init__(); self.original_input = input_file; self.processed_files = set(); self.queue = []; self.findings = []
    
# #     def log(self, msg): self.log_signal.emit(f"[{time.strftime('%H:%M:%S')}] {msg}")

# #     def run(self):
# #         try:
# #             self.status_signal.emit("INITIALIZING")
# #             self.progress_signal.emit(0)
# #             clean = os.path.splitext(os.path.basename(self.original_input))[0].replace(" ", "_")
# #             case = os.path.join(WORKSPACE_DIR, f"CASE_{int(time.time())}_{clean}")
# #             self.src_root = os.path.join(case, "RECOVERED_SOURCE")
# #             os.makedirs(self.src_root, exist_ok=True)
            
# #             # --- PHASE 1: RECURSIVE RECOVERY ---
# #             self.queue.append(self.original_input)
            
# #             while self.queue:
# #                 current_target = self.queue.pop(0)
# #                 if current_target in self.processed_files: continue
# #                 self.processed_files.add(current_target)
                
# #                 self.process_single_binary(current_target, self.src_root)
# #                 self.scan_for_embedded_binaries(self.src_root)

# #             # --- PHASE 2: VULNERABILITY SCANNING ---
# #             self.status_signal.emit("VULN SCANNING")
# #             self.log("🛡️ Scanning all recovered source code for vulnerabilities...")
# #             self.run_vapt_scan(self.src_root)

# #             # --- FINISH ---
# #             self.status_signal.emit("COMPLETE")
# #             self.progress_signal.emit(100)
# #             self.finished_signal.emit(self.src_root, self.findings)
            
# #         except Exception as e:
# #             self.log(f"CRITICAL ERROR: {e}"); self.log(traceback.format_exc()); self.status_signal.emit("ERROR")

# #     def process_single_binary(self, target_path, output_root):
# #         fname = os.path.basename(target_path)
# #         self.log(f"Analyzing: {fname}")
# #         ftype = self.detect_sig(target_path)
# #         self.log(f"   -> Detected: {ftype}")
# #         sub_out = os.path.join(output_root, fname + "_source")
# #         os.makedirs(sub_out, exist_ok=True)

# #         if ftype == "DOT_NET":
# #             self.status_signal.emit(f"C# : {fname}")
# #             if os.path.exists(TOOL_ILSPY_EXE): subprocess.run([TOOL_ILSPY_EXE, target_path, "-p", "-o", sub_out])
# #             elif os.path.exists(TOOL_ILSPY_DLL): subprocess.run(["dotnet", TOOL_ILSPY_DLL, target_path, "-p", "-o", sub_out])
# #             StructureNormalizer.reorganize_csharp(sub_out)

# #         elif ftype == "JAVA":
# #             self.status_signal.emit(f"JAVA : {fname}")
# #             subprocess.run([TOOL_JADX, "-d", sub_out, "--deobf", "--deobf-use-sourcename", "-j", "4", target_path], stdout=subprocess.DEVNULL)

# #         elif ftype == "PYTHON":
# #             self.status_signal.emit(f"PYTHON : {fname}")
# #             shutil.copy2(target_path, os.path.join(sub_out, fname))
# #             subprocess.run([sys.executable, TOOL_EXTRACTOR, os.path.join(sub_out, fname)], cwd=sub_out, stdout=subprocess.DEVNULL)
# #             for root, dirs, files in os.walk(sub_out):
# #                 for file in files:
# #                     if file.endswith(".pyc"): self.process_pyc(os.path.join(root, file))

# #         elif ftype == "NATIVE":
# #             if os.path.getsize(target_path) > 10 * 1024:
# #                 self.status_signal.emit(f"NATIVE : {fname}")
# #                 ghidra = GhidraEngine(self.log_signal, self.status_signal)
# #                 ghidra.run(target_path, sub_out)
# #             else: self.log("Skipping Native Analysis (File too small)")

# #     def scan_for_embedded_binaries(self, root_folder):
# #         for root, dirs, files in os.walk(root_folder):
# #             for file in files:
# #                 path = os.path.join(root, file)
# #                 if path in self.processed_files or path in self.queue: continue
# #                 if file.lower().endswith(('.dll', '.exe', '.jar', '.so', '.pyd')):
# #                     if self.detect_sig(path) != "UNKNOWN":
# #                         self.log(f"🔎 Found embedded: {file}")
# #                         self.queue.append(path)

# #     def run_vapt_scan(self, root_folder):
# #         total_files = sum([len(files) for r, d, files in os.walk(root_folder)])
# #         scanned = 0
# #         for root, dirs, files in os.walk(root_folder):
# #             for file in files:
# #                 if file.endswith(('.cs', '.java', '.py', '.c', '.cpp', '.xml', '.json')):
# #                     scanned += 1
# #                     if total_files > 0 and scanned % 50 == 0: 
# #                         self.progress_signal.emit(int((scanned/total_files)*100))
# #                     try:
# #                         with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
# #                             content = f.read()
# #                             hits = VulnerabilityScanner.scan_file(os.path.join(root, file), content)
# #                             if hits: self.findings.extend(hits)
# #                     except: pass
        
# #         self.log(f"VAPT Scan Complete. Found {len(self.findings)} Vulnerabilities.")
# #         report = ReportGenerator.generate_html(os.path.dirname(root_folder), self.findings)
# #         self.log(f"📄 Report: {report}")

# #     def detect_sig(self, path):
# #         try:
# #             with open(path, 'rb') as f: h = f.read(4194304)
# #             if h.startswith(b'\xCA\xFE\xBA\xBE') or path.endswith(('.jar', '.war')): return "JAVA"
# #             if b'MZ' in h:
# #                 if b'MEI' in h or b'PYINSTALLER' in h or b'pyi-windows' in h: return "PYTHON"
# #                 if b'BSJB' in h or b'mscorlib' in h or b'mscoree.dll' in h: return "DOT_NET"
# #                 return "NATIVE"
# #             if b'ELF' in h: return "NATIVE"
# #         except: pass
# #         return "UNKNOWN"

# #     def process_pyc(self, pyc):
# #         final = None
# #         if os.path.exists(TOOL_PYCDC):
# #             try:
# #                 res = subprocess.run([TOOL_PYCDC, pyc], capture_output=True, text=True, timeout=5)
# #                 if res.stdout and "def " in res.stdout: final = res.stdout
# #             except: pass
# #         if not final: final = MagicPatcher.try_patch(pyc)
# #         if not final:
# #             try:
# #                 with open(pyc, 'rb') as f: data = f.read(); code_obj = marshal.loads(data[16:])
# #                 final = StackDecompilerV2(code_obj).decompile()
# #             except: pass
# #         full = OmniscientEngine.generate_full_view(pyc, final or "# FAIL")
# #         with open(pyc.replace(".pyc", ".py"), "w", encoding="utf-8") as f: f.write(full)

# # # ==============================================================================
# # #  GUI (HYBRID)
# # # ==============================================================================
# # STYLES = """
# #     QMainWindow { background-color: #F5F7FA; }
# #     QWidget { font-family: 'Segoe UI', 'Arial', sans-serif; font-size: 13px; color: #2D3436; }
# #     QFrame#Header { background-color: #FFFFFF; border-bottom: 3px solid #C0392B; }
# #     QTextEdit { background-color: #FFFFFF; color: #2D3436; border: 1px solid #B2BEC3; font-family: 'Consolas', monospace; font-size: 12px; }
# #     QTreeWidget, QTableWidget { background-color: #FFFFFF; border: 1px solid #B2BEC3; }
# #     QHeaderView::section { background-color: #DFE6E9; padding: 5px; font-weight: bold; border: none; }
# #     QLabel#Title { color: #C0392B; font-weight: 900; font-size: 24px; }
# #     QLabel#Subtitle { color: #2D3436; font-weight: bold; font-size: 11px; }
# #     QProgressBar { border: 1px solid #B2BEC3; background: #FFFFFF; height: 8px; text-align: center; }
# #     QProgressBar::chunk { background-color: #C0392B; }
# # """

# # class PentestGUI(QMainWindow):
# #     def __init__(self):
# #         super().__init__()
# #         self.setWindowTitle("VU RED TEAM TOOLKIT v1.3")
# #         self.resize(1500, 950)
# #         self.setAcceptDrops(True)
# #         if os.path.exists(LOGO_PATH): self.setWindowIcon(QIcon(LOGO_PATH))
# #         self.initUI()

# #     def initUI(self):
# #         self.setStyleSheet(STYLES)
# #         w = QWidget(); self.setCentralWidget(w); l = QVBoxLayout(); w.setLayout(l); l.setContentsMargins(0,0,0,0)
        
# #         h = QFrame(); h.setObjectName("Header"); h.setFixedHeight(80); hl = QHBoxLayout(); hl.setContentsMargins(20, 10, 20, 10)
# #         if os.path.exists(LOGO_PATH):
# #             lbl = QLabel(); px = QPixmap(LOGO_PATH); lbl.setPixmap(px.scaled(60, 60, Qt.KeepAspectRatio, Qt.SmoothTransformation)); hl.addWidget(lbl); hl.addSpacing(15)
        
# #         v = QVBoxLayout()
# #         t = QLabel("VU RED TEAM TOOLKIT"); t.setObjectName("Title"); v.addWidget(t)
# #         s = QLabel("DEEP RECURSIVE SOURCE RECOVERY & VULNERABILITY ANALYSIS"); s.setObjectName("Subtitle"); v.addWidget(s)
# #         hl.addLayout(v); hl.addStretch()
# #         self.pill = QLabel(" READY "); self.pill.setStyleSheet("border: 2px solid #C0392B; color: #C0392B; border-radius: 4px; padding: 6px 12px; font-weight: bold; font-family: 'Consolas';"); hl.addWidget(self.pill)
# #         h.setLayout(hl); l.addWidget(h)
        
# #         self.tabs = QTabWidget()
# #         self.tabs.setStyleSheet("QTabBar::tab { height: 35px; width: 150px; font-weight: bold; } QTabBar::tab:selected { color: #C0392B; }")
        
# #         # Tab 1
# #         tab1 = QWidget(); t1 = QHBoxLayout(); tab1.setLayout(t1)
# #         self.log = QTextEdit(); self.log.setReadOnly(True)
# #         self.tree = QTreeWidget(); self.tree.setHeaderLabels(["File Name", "Type"]); self.tree.setColumnWidth(0, 500)
# #         self.tree.itemDoubleClicked.connect(self.open_item)
# #         self.tree.setContextMenuPolicy(Qt.CustomContextMenu); self.tree.customContextMenuRequested.connect(self.menu)
# #         spl = QSplitter(Qt.Horizontal); spl.addWidget(self.log); spl.addWidget(self.tree); spl.setSizes([400, 1000])
# #         t1.addWidget(spl)
        
# #         # Tab 2
# #         tab2 = QWidget(); t2 = QVBoxLayout(); tab2.setLayout(t2)
# #         self.vuln_table = QTableWidget(); self.vuln_table.setColumnCount(4); self.vuln_table.setHorizontalHeaderLabels(["SEVERITY", "VULNERABILITY", "FILE", "MATCH DETAILS"])
# #         self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
# #         t2.addWidget(self.vuln_table)
        
# #         self.tabs.addTab(tab1, "📂 SOURCE EXPLORER"); self.tabs.addTab(tab2, "🛡️ THREAT INTEL")
# #         l.addWidget(self.tabs)
# #         self.prog = QProgressBar(); self.prog.setTextVisible(False); self.prog.setRange(0, 100); l.addWidget(self.prog)

# #     def dragEnterEvent(self, e): e.accept()
# #     def dropEvent(self, e): self.start([u.toLocalFile() for u in e.mimeData().urls()][0])
# #     def start(self, path):
# #         self.log.clear(); self.tree.clear(); self.vuln_table.setRowCount(0); self.prog.setValue(0); self.pill.setText(" PROCESSING ")
# #         self.th = DecompilerThread(path)
# #         self.th.log_signal.connect(self.log.append); self.th.status_signal.connect(self.pill.setText); self.th.progress_signal.connect(self.prog.setValue); self.th.finished_signal.connect(self.done); self.th.start()
# #     def done(self, path, findings):
# #         self.prog.setValue(100); self.pill.setText(" COMPLETE "); self.populate_tree(path); self.populate_vulns(findings)
# #         if findings: self.tabs.setCurrentIndex(1)
# #     def populate_tree(self, path):
# #         root = QTreeWidgetItem(self.tree); root.setText(0, os.path.basename(path)); root.setExpanded(True); self.add_rec(root, path)
# #     def add_rec(self, p, path):
# #         try:
# #             for e in os.scandir(path):
# #                 if e.name.endswith(('.dll','.png','.ico')): continue
# #                 i = QTreeWidgetItem(p); i.setText(0, e.name); i.setData(0, Qt.UserRole, e.path)
# #                 if e.name.endswith(".cs"): i.setText(1, "C# SOURCE"); i.setForeground(1, QColor("#27AE60"))
# #                 elif e.name.endswith(".py"): i.setText(1, "PYTHON SOURCE"); i.setForeground(1, QColor("#27AE60"))
# #                 elif e.name.endswith((".c", ".cpp")): i.setText(1, "NATIVE C"); i.setForeground(1, QColor("#8E44AD"))
# #                 if e.is_dir(): self.add_rec(i, e.path)
# #         except: pass
# #     def populate_vulns(self, findings):
# #         self.vuln_table.setRowCount(len(findings))
# #         for r, f in enumerate(findings):
# #             sev = QTableWidgetItem(f['severity']); sev.setTextAlignment(Qt.AlignCenter)
# #             if f['severity'] == "CRITICAL": sev.setBackground(QBrush(QColor("#C0392B"))); sev.setForeground(QBrush(QColor("white")))
# #             elif f['severity'] == "HIGH": sev.setBackground(QBrush(QColor("#E67E22"))); sev.setForeground(QBrush(QColor("white")))
# #             else: sev.setBackground(QBrush(QColor("#F1C40F")))
# #             self.vuln_table.setItem(r, 0, sev); self.vuln_table.setItem(r, 1, QTableWidgetItem(f['name'])); self.vuln_table.setItem(r, 2, QTableWidgetItem(f['file'])); self.vuln_table.setItem(r, 3, QTableWidgetItem(f['matches']))
# #     def menu(self, pos):
# #         sel = self.tree.selectedItems()
# #         if sel: m = QMenu(); a = QAction(f"BUNDLE FILES", self); a.triggered.connect(lambda: self.bundle(sel)); m.addAction(a); m.exec_(self.tree.viewport().mapToGlobal(pos))
# #     def bundle(self, items):
# #         p = os.path.join(os.path.dirname(items[0].data(0, Qt.UserRole)), "BUNDLE.txt")
# #         c = "Analysis Bundle:\n\n"; 
# #         for i in items:
# #             with open(i.data(0, Qt.UserRole), "r", errors='ignore') as f: c += f"--- {i.text(0)} ---\n{f.read()}\n\n"
# #         with open(p, "w", encoding="utf-8") as f: f.write(c); os.startfile(p)
# #     def open_item(self, i): 
# #         p = i.data(0, Qt.UserRole)
# #         if p and os.path.exists(p) and not os.path.isdir(p): os.startfile(p)

# # if __name__ == "__main__":
# #     multiprocessing.freeze_support()
# #     app = QApplication(sys.argv)
# #     window = PentestGUI()
# #     window.show()
# #     sys.exit(app.exec_())



























import sys
import os
import shutil
import subprocess
import multiprocessing
import dis
import marshal
import time
import io
import types
import re
import traceback
import base64
import json
from datetime import datetime
from contextlib import redirect_stdout
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QTextEdit, QSplitter, QTreeWidget, QTreeWidgetItem, 
                             QFrame, QProgressBar, QAbstractItemView, QMenu, QAction, 
                             QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QIcon, QPixmap, QBrush

# ==============================================================================
#  1. GLOBAL CONFIGURATION & STYLES
# ==============================================================================
ARSENAL_BASE = r"C:\Users\PC\Desktop\RE_Arsenal"
WORKSPACE_DIR = os.path.join(ARSENAL_BASE, "Workspace")
LOGO_PATH = r"C:\Users\PC\Desktop\RE_Arsenal\Scripts\Icon\vu_logo_bg.png"

# MAX RAM ALLOCATION
GHIDRA_RAM_LIMIT = "26G"
GHIDRA_CPU_LIMIT = "2"

STYLES = """
    QMainWindow { background-color: #F5F7FA; }
    QWidget { font-family: 'Segoe UI', 'Arial', sans-serif; font-size: 13px; color: #2D3436; }
    QFrame#Header { background-color: #FFFFFF; border-bottom: 3px solid #C0392B; }
    QTextEdit { background-color: #FFFFFF; color: #2D3436; border: 1px solid #B2BEC3; font-family: 'Consolas', monospace; font-size: 12px; }
    QTreeWidget, QTableWidget { background-color: #FFFFFF; border: 1px solid #B2BEC3; }
    QHeaderView::section { background-color: #DFE6E9; padding: 5px; font-weight: bold; border: none; }
    QLabel#Title { color: #C0392B; font-weight: 900; font-size: 24px; }
    QLabel#Subtitle { color: #2D3436; font-weight: bold; font-size: 11px; }
    QProgressBar { border: 1px solid #B2BEC3; background: #FFFFFF; height: 8px; text-align: center; }
    QProgressBar::chunk { background-color: #C0392B; }
"""

# TOOLS
TOOL_EXTRACTOR = os.path.join(ARSENAL_BASE, r"Tools\pyinstxtractor\pyinstxtractor.py")
TOOL_JADX = os.path.join(ARSENAL_BASE, r"Tools\jadx\bin\jadx.bat")
TOOL_PYCDC = os.path.join(ARSENAL_BASE, r"Tools\pycdc\pycdc.exe")
TOOL_ILSPY_EXE = os.path.join(ARSENAL_BASE, r"Tools\ilspy\ilspycmd.exe")
TOOL_ILSPY_DLL = os.path.join(ARSENAL_BASE, r"Tools\ilspy\ilspycmd.dll")
TOOL_GHIDRA_HEADLESS = os.path.join(ARSENAL_BASE, r"Tools\ghidra\support\analyzeHeadless.bat")

# VULN DB
VULN_DB = [
    {"name": "AWS Access Key", "regex": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "severity": "CRITICAL", "desc": "Hardcoded AWS Credential"},
    {"name": "Private Key", "regex": r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----", "severity": "CRITICAL", "desc": "Embedded Cryptographic Private Key"},
    {"name": "Google API Key", "regex": r"AIza[0-9A-Za-z\\-_]{35}", "severity": "CRITICAL", "desc": "Hardcoded Google Cloud API Key"},
    {"name": "Hardcoded Password", "regex": r"(password|passwd|pwd|secret|token|api_key)\s*=\s*['\"][\w@#$%]{5,}['\"]", "severity": "HIGH", "desc": "Possible hardcoded credential"},
    {"name": "Command Injection", "regex": r"(os\.system|subprocess\.call|Runtime\.getRuntime\(\)\.exec|system\()", "severity": "HIGH", "desc": "Execution of OS commands"},
    {"name": "Unsafe Deserialization", "regex": r"(pickle\.loads|Marshal\.load|ObjectInputStream)", "severity": "HIGH", "desc": "Potential RCE via deserialization"},
    {"name": "Weak Hashing (MD5)", "regex": r"(MD5|md5)", "severity": "MEDIUM", "desc": "Use of broken cryptographic algorithm"},
    {"name": "Internal IP Address", "regex": r"\b192\.168\.\d{1,3}\.\d{1,3}\b|\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "severity": "MEDIUM", "desc": "Hardcoded Internal IP"},
]

# ==============================================================================
#  2. VAPT ENGINES (MOVED TO TOP TO FIX NAME ERROR)
# ==============================================================================
class VulnerabilityScanner:
    @staticmethod
    def scan_file(filepath, content):
        findings = []
        for sig in VULN_DB:
            matches = re.findall(sig['regex'], content, re.IGNORECASE)
            if matches:
                unique = list(set(matches))[:5]
                findings.append({ "severity": sig['severity'], "name": sig['name'], "desc": sig['desc'], "file": os.path.basename(filepath), "matches": str(unique), "path": filepath })
        return findings

class ReportGenerator:
    @staticmethod
    def generate_html(case_dir, findings):
        report_path = os.path.join(case_dir, "VULNERABILITY_REPORT.html")
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
        for f in findings: stats[f['severity']] = stats.get(f['severity'], 0) + 1
        html = f"""<html><head><title>VU CodeShield Report</title>
        <style>body{{font-family:Arial;background:#F5F7FA;padding:20px;}}h1{{color:#C0392B;}}
        .summary{{display:flex;gap:20px;margin-bottom:30px;}} .card{{background:white;padding:20px;border-radius:5px;width:200px;text-align:center;box-shadow:0 2px 5px rgba(0,0,0,0.1);}}
        .crit{{border-top:5px solid #C0392B;color:#C0392B;font-weight:bold;}} .high{{border-top:5px solid #E67E22;color:#E67E22;font-weight:bold;}}
        table{{width:100%;border-collapse:collapse;background:white;}} th,td{{padding:12px;text-align:left;border-bottom:1px solid #ddd;}} th{{background:#2C3E50;color:white;}}
        </style></head><body><h1>🛡️ VAPT REPORT</h1><p>Target: {os.path.basename(case_dir)}</p>
        <div class="summary"><div class="card crit">CRITICAL<br>{stats['CRITICAL']}</div><div class="card high">HIGH<br>{stats['HIGH']}</div></div>
        <table><tr><th>SEVERITY</th><th>ISSUE</th><th>FILE</th><th>EVIDENCE</th></tr>"""
        for f in findings: html += f"<tr><td>{f['severity']}</td><td><b>{f['name']}</b></td><td>{f['file']}</td><td><code>{f['matches'][:80]}...</code></td></tr>"
        html += "</table></body></html>"
        with open(report_path, "w", encoding="utf-8") as f: f.write(html)
        return report_path

# ==============================================================================
#  3. HELPER ENGINES
# ==============================================================================
class StructureBooster:
    @staticmethod
    def boost(code):
        lines = []
        ptr_pattern = re.compile(r'\*\s*\(\w+\s*\*\)\s*\(([\w_]+)\s*\+\s*(0x[\da-f]+)\)')
        arr_pattern = re.compile(r'\*\s*\(\w+\s*\*\)\s*\(([\w_]+)\s*\+\s*([\w_]+)\s*\*\s*(\d+)\)')
        for line in code.splitlines():
            match = ptr_pattern.search(line)
            if match:
                var, offset = match.group(1), match.group(2)
                line = line.replace(match.group(0), f"{var}->field_{offset}")
            match_arr = arr_pattern.search(line)
            if match_arr:
                var, idx = match_arr.group(1), match_arr.group(2)
                line = line.replace(match.group(0), f"{var}[{idx}]")
            lines.append(line)
        return "\n".join(lines)

class SemanticRenamer:
    PATTERNS = [
        (r"open\s*\(([^,]+),\s*['\"]r['\"]", "file_path"),
        (r"read\s*\(([^)]+)\)", "file_stream"),
        (r"socket\.connect\s*\(\s*\(([^,]+),\s*([^)]+)\)\s*\)", "target_host"),
        (r"base64\.b64decode\s*\(([^)]+)\)", "encoded_data"),
        (r"sqlite3\.connect\s*\(([^)]+)\)", "db_path"),
        (r"0x5a4d", "MZ_HEADER"), (r"0x4550", "PE_SIGNATURE"),
    ]
    @staticmethod
    def process(code):
        renames = {}
        for line in code.splitlines():
            for pattern, hint in SemanticRenamer.PATTERNS:
                m = re.search(pattern, line)
                if m:
                    if "0x" in pattern and "FUN_" in code: code = code.replace("FUN_", f"FUNC_{hint}_")
                    m_var = re.search(r"\b([a-zA-Z_]\w*)\s*=", line)
                    if m_var:
                        var = m_var.group(1).strip()
                        if len(var) < 15 and "param" not in var: renames[var] = hint
        new_code = code
        for old, new in renames.items():
            new_code = re.sub(r'\b' + re.escape(old) + r'\b', new, new_code)
        return new_code

class TypeInferencer:
    @staticmethod
    def process(code):
        lines = []
        for line in code.splitlines():
            line = re.sub(r'(\w+)\s*=\s*\[\]', r'\1: list = []', line)
            line = re.sub(r'(\w+)\s*=\s*\{\}', r'\1: dict = {}', line)
            lines.append(line)
        return "\n".join(lines)

class AdvancedSanitizer:
    @staticmethod
    def clean_file(filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f: code = f.read()
            code = code.replace("undefined4", "int").replace("undefined2", "short").replace("undefined1", "byte").replace("undefined", "void*")
            code = code.replace("uint", "unsigned int").replace("ushort", "unsigned short")
            code = re.sub(r"__(fast|this|std|c)call", "", code)
            code = re.sub(r'CONCAT\d+\(', '(', code)
            code = StructureBooster.boost(code)
            lines = []
            for line in code.splitlines():
                l = line.strip()
                if l == "return": continue
                if re.match(r"^(\w+)\s*=\s*\1;?$", l): continue
                lines.append(line)
            with open(filepath, "w", encoding="utf-8") as f: f.write("\n".join(lines))
            return True
        except: return False

    @staticmethod
    def clean(source_code):
        cleaned = re.sub(r"NULL\s*\|\s*self\s*\+\s*", "self.", source_code)
        cleaned = re.sub(r"NULL\s*\+\s*", "", cleaned)
        return cleaned

class MagicPatcher:
    HEADERS = { "3.12": b'\xcb\x0d\x0d\x0a', "3.11": b'\xa7\x0d\x0d\x0a', "3.10": b'\x6f\x0d\x0d\x0a', "3.9": b'\x61\x0d\x0d\x0a' }
    @staticmethod
    def try_patch(pyc_path):
        try:
            with open(pyc_path, "rb") as f: raw = f.read()
            if len(raw) < 16: return None
        except: return None
        for ver, magic in MagicPatcher.HEADERS.items():
            tmp = pyc_path + f".{ver}.pyc"
            with open(tmp, "wb") as f: f.write(magic + b'\x00'*12 + raw)
            try:
                res = subprocess.run([TOOL_PYCDC, tmp], capture_output=True, text=True, timeout=3)
                os.remove(tmp)
                if res.stdout and ("def " in res.stdout or "import " in res.stdout): return res.stdout
            except: 
                if os.path.exists(tmp): os.remove(tmp)
        return None

# ==============================================================================
#  4. DECOMPILERS
# ==============================================================================
class StackDecompilerV2:
    def __init__(self, code_obj, indent_level=0):
        self.co = code_obj; self.output = []; self.indent_level = indent_level
    def indent(self): return "    " * self.indent_level
    def decompile(self):
        name = self.co.co_name
        if name == "__init__": self.output.insert(0, f"{self.indent()}class RecoveredClass:")
        args = ", ".join(self.co.co_varnames[:self.co.co_argcount])
        self.output.append(f"{self.indent()}def {name}({args}):")
        self.indent_level += 1
        try:
            instructions = list(dis.get_instructions(self.co))
            stack = []
            for instr in instructions:
                op, arg, repr_val = instr.opname, instr.argval, instr.argrepr
                if "LOAD_CONST" in op: stack.append(repr(arg))
                elif "LOAD_" in op: stack.append(str(repr_val))
                elif "STORE_" in op:
                    if stack:
                        val = stack.pop()
                        if "<code object" not in val: self.output.append(f"{self.indent()}{repr_val} = {val}")
                elif "RETURN_VALUE" in op:
                    if stack: self.output.append(f"{self.indent()}return {stack.pop()}")
                elif "CALL" in op:
                    count = instr.arg; c_args = []
                    for _ in range(count):
                        if stack: c_args.insert(0, stack.pop())
                    func = stack.pop() if stack else "func"
                    stack.append(f"{func}({', '.join(c_args)})")
        except: pass
        for const in self.co.co_consts:
            if isinstance(const, types.CodeType):
                self.output.append(""); self.output.append(StackDecompilerV2(const, self.indent_level).decompile())
        return "\n".join(self.output)

class OmniscientEngine:
    @staticmethod
    def generate_full_view(pyc_path, source_code):
        code = AdvancedSanitizer.clean(source_code)
        code = TypeInferencer.process(code)
        code = SemanticRenamer.process(code)
        asm = "Bytecode Unavailable"
        try:
            with open(pyc_path, 'rb') as f: 
                data = f.read()
                if len(data) > 16:
                    code_obj = marshal.loads(data[16:])
                    f_out = io.StringIO(); dis.dis(code_obj, file=f_out); asm = f_out.getvalue()
        except: pass
        return f"# FILE: {os.path.basename(pyc_path)}\n# RE-TOOLKIT RECONSTRUCTION:\n{code}\n\n# RAW BYTECODE:\n{asm}"

GHIDRA_EXPORT_SCRIPT = """
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType
args = getScriptArgs()

if len(args) > 0:
    out_dir = args[0]
    if not os.path.exists(out_dir): os.makedirs(out_dir)
    program = currentProgram; decomplib = DecompInterface(); decomplib.openProgram(program); monitor = ConsoleTaskMonitor()
    listing = program.getListing(); fm = program.getFunctionManager()
    
    # 1. HEURISTIC NAMING
    print("VU-LOG: Applying String Heuristics...")
    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        if "String" in str(data.getDataType()):
            val = str(data.getValue())
            clean = "".join(c for c in val if c.isalnum())
            if len(clean) > 4:
                refs = program.getReferenceManager().getReferencesTo(data.getAddress())
                for ref in refs:
                    func = fm.getFunctionContaining(ref.getFromAddress())
                    if func and "FUN_" in func.getName():
                        func.setName("FUNC_" + clean[:15], SourceType.USER_DEFINED)

    # 2. DECOMPILE
    iterator = listing.getFunctions(True)
    count = 0
    print("VU-LOG: Starting Decompilation...")
    
    while iterator.hasNext():
        func = iterator.next(); count += 1
        if count % 20 == 0: print("VU-LOG: Processing #" + str(count) + " - " + func.getName())
        try:
            results = decomplib.decompileFunction(func, 5, monitor)
            if results.decompileCompleted():
                code = results.getDecompiledFunction().getC()
                fname = func.getName()
                if "thunk_" in fname: continue
                safe = "".join(x for x in fname if x.isalnum() or x in "_")
                if not safe: safe = "UNKNOWN"
                with open(os.path.join(out_dir, safe + ".c"), "w") as f:
                    f.write("// RECOVERED: " + fname + "\\n// ADDRESS: " + str(func.getEntryPoint()) + "\\n\\n" + code)
        except: pass
    print("VU-LOG: Analysis Complete.")
"""

class GhidraEngine:
    def __init__(self, log_signal, status_signal):
        self.log_signal = log_signal; self.status_signal = status_signal
    
    def optimize_memory(self):
        try:
            prop_file = os.path.join(os.path.dirname(TOOL_GHIDRA_HEADLESS), "launch.properties")
            if os.path.exists(prop_file):
                with open(prop_file, 'r') as f: lines = f.readlines()
                clean_lines = [l for l in lines if "VMARGS=-Xmx" not in l and "cpu.core.limit" not in l]
                clean_lines.append(f"\nVMARGS=-Xmx{GHIDRA_RAM_LIMIT}\n")
                clean_lines.append(f"VMARGS=-Dcpu.core.limit={GHIDRA_CPU_LIMIT}\n")
                with open(prop_file, 'w') as f: f.writelines(clean_lines)
                self.log_signal.emit(f"🚀 CONFIG UPDATED: RAM={GHIDRA_RAM_LIMIT} | CPU={GHIDRA_CPU_LIMIT} Cores")
        except Exception as e: self.log_signal.emit(f"⚠️ Config Error: {e}")

    def run(self, target_path, output_dir):
        if not os.path.exists(TOOL_GHIDRA_HEADLESS):
            self.log_signal.emit("❌ Ghidra Headless not found."); return
        self.optimize_memory()
        self.log_signal.emit("🚀 Launching GHIDRA C/C++ ENGINE...")
        self.log_signal.emit("⏳ Streaming analysis logs...")
        self.status_signal.emit("GHIDRA RUNNING")
        
        script_path = os.path.join(WORKSPACE_DIR, "ghidra_export.py")
        with open(script_path, "w") as f: f.write(GHIDRA_EXPORT_SCRIPT)
        proj_path = os.path.join(WORKSPACE_DIR, "Ghidra_Proj"); proj_name = f"P_{int(time.time())}"
        if not os.path.exists(proj_path): os.makedirs(proj_path)
        
        cmd = [TOOL_GHIDRA_HEADLESS, proj_path, proj_name, "-import", target_path, "-postScript", script_path, output_dir, "-deleteProject"]
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
            for line in process.stdout:
                clean = line.strip()
                if "VU-LOG" in clean: self.log_signal.emit(f"⚙️ {clean.split('VU-LOG:')[-1].strip()}")
                elif "INFO" in clean or "REPORT" in clean: 
                    msg = clean.split("INFO")[-1].split("REPORT")[-1].strip()[:80]
                    self.log_signal.emit(f"📝 GHIDRA: {msg}...")
                elif "ERROR" in clean: 
                    if "PNG" not in clean: self.log_signal.emit(f"⚠️ {clean}")
            process.wait()
            self.log_signal.emit("✅ Ghidra Finished.")
        except Exception as e: self.log_signal.emit(f"❌ Critical Error: {e}")

# ==============================================================================
#  5. WORKER THREAD & GUI
# ==============================================================================
class StructureNormalizer:
    @staticmethod
    def reorganize_csharp(source_root):
        for root, dirs, files in os.walk(source_root):
            for file in files:
                if not file.endswith(".cs"): continue
                try:
                    with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.strip().startswith("namespace "):
                                ns = line.strip().split(" ")[1].split(";")[0]
                                tgt = os.path.join(source_root, ns.replace(".", os.sep))
                                if not os.path.exists(tgt): os.makedirs(tgt)
                                shutil.move(os.path.join(root, file), os.path.join(tgt, file)); break
                except: pass

class DecompilerThread(QThread):
    log_signal = pyqtSignal(str); finished_signal = pyqtSignal(str, list)
    status_signal = pyqtSignal(str); progress_signal = pyqtSignal(int)
    pulse_signal = pyqtSignal(bool)
    
    def __init__(self, input_file): 
        super().__init__(); self.original_input = input_file; self.processed_files = set(); self.queue = []; self.findings = []
    
    def log(self, msg): self.log_signal.emit(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def run(self):
        try:
            self.status_signal.emit("INITIALIZING")
            self.progress_signal.emit(0)
            clean = os.path.splitext(os.path.basename(self.original_input))[0].replace(" ", "_")
            case = os.path.join(WORKSPACE_DIR, f"CASE_{int(time.time())}_{clean}")
            self.src_root = os.path.join(case, "RECOVERED_SOURCE")
            os.makedirs(self.src_root, exist_ok=True)
            self.queue.append(self.original_input)
            
            while self.queue:
                current_target = self.queue.pop(0)
                if current_target in self.processed_files: continue
                self.processed_files.add(current_target)
                self.process_single_binary(current_target, self.src_root)
                self.scan_for_embedded_binaries(self.src_root)

            self.status_signal.emit("SANITIZING")
            self.log("🧹 Running Structure Booster...")
            self.sanitize_native_output(self.src_root)

            self.status_signal.emit("VULN SCANNING")
            self.log("🛡️ Scanning for Vulnerabilities...")
            self.run_vapt_scan(self.src_root)

            self.status_signal.emit("COMPLETE")
            self.progress_signal.emit(100)
            self.finished_signal.emit(self.src_root, self.findings)
        except Exception as e:
            self.log(f"CRITICAL ERROR: {e}"); self.log(traceback.format_exc()); self.status_signal.emit("ERROR")

    def sanitize_native_output(self, root_folder):
        count = 0
        for root, dirs, files in os.walk(root_folder):
            for file in files:
                if file.endswith(".c"):
                    if AdvancedSanitizer.clean_file(os.path.join(root, file)): count += 1
        self.log(f"✅ Sanitized {count} Native Files.")

    def process_single_binary(self, target_path, output_root):
        fname = os.path.basename(target_path)
        self.log(f"Analyzing: {fname}")
        ftype = self.detect_sig(target_path)
        self.log(f"   -> Detected: {ftype}")
        sub_out = os.path.join(output_root, fname + "_source")
        os.makedirs(sub_out, exist_ok=True)

        if ftype == "DOT_NET":
            self.status_signal.emit(f"C# : {fname}")
            if os.path.exists(TOOL_ILSPY_EXE): subprocess.run([TOOL_ILSPY_EXE, target_path, "-p", "-o", sub_out])
            elif os.path.exists(TOOL_ILSPY_DLL): subprocess.run(["dotnet", TOOL_ILSPY_DLL, target_path, "-p", "-o", sub_out])
            StructureNormalizer.reorganize_csharp(sub_out)
        elif ftype == "JAVA":
            self.status_signal.emit(f"JAVA : {fname}")
            subprocess.run([TOOL_JADX, "-d", sub_out, "--deobf", "--deobf-use-sourcename", "-j", "4", target_path], stdout=subprocess.DEVNULL)
        elif ftype == "PYTHON":
            self.status_signal.emit(f"PYTHON : {fname}")
            target_copy = os.path.join(sub_out, fname)
            if not os.path.exists(target_copy):
                try: shutil.copy2(target_path, target_copy)
                except: self.log(f"⚠️ Warning: Could not copy {fname}. Skipping.")
            if os.path.exists(target_copy):
                subprocess.run([sys.executable, TOOL_EXTRACTOR, target_copy], cwd=sub_out, stdout=subprocess.DEVNULL)
                for root, dirs, files in os.walk(sub_out):
                    for file in files:
                        if file.endswith(".pyc"): self.process_pyc(os.path.join(root, file))
        elif ftype == "NATIVE":
            if os.path.getsize(target_path) > 100 * 1024:
                self.status_signal.emit(f"NATIVE : {fname}")
                self.pulse_signal.emit(True)
                ghidra = GhidraEngine(self.log_signal, self.status_signal)
                ghidra.run(target_path, sub_out)
                self.pulse_signal.emit(False)
            else: self.log("Skipping Native Analysis (File too small)")

    def scan_for_embedded_binaries(self, root_folder):
        for root, dirs, files in os.walk(root_folder):
            for file in files:
                path = os.path.join(root, file)
                if path in self.processed_files or path in self.queue: continue
                if file.lower().endswith(('.dll', '.exe', '.jar', '.so', '.pyd')):
                    if self.detect_sig(path) != "UNKNOWN":
                        self.log(f"🔎 Found embedded: {file}")
                        self.queue.append(path)

    def run_vapt_scan(self, root_folder):
        total_files = sum([len(files) for r, d, files in os.walk(root_folder)])
        scanned = 0
        for root, dirs, files in os.walk(root_folder):
            for file in files:
                if file.endswith(('.cs', '.java', '.py', '.c', '.cpp', '.xml', '.json')):
                    scanned += 1
                    if total_files > 0 and scanned % 50 == 0: self.progress_signal.emit(int((scanned/total_files)*100))
                    try:
                        with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                            hits = VulnerabilityScanner.scan_file(os.path.join(root, file), f.read())
                            if hits: self.findings.extend(hits)
                    except: pass
        self.log(f"VAPT Scan Complete. Found {len(self.findings)} Vulnerabilities.")
        ReportGenerator.generate_html(os.path.dirname(root_folder), self.findings)

    def detect_sig(self, path):
        try:
            with open(path, 'rb') as f: 
                # Deep Inspection (20MB)
                h = f.read(20 * 1024 * 1024) 
            
            # 1. JAVA
            if h.startswith(b'\xCA\xFE\xBA\xBE') or path.endswith(('.jar', '.war')): return "JAVA"
            
            # 2. WINDOWS PE
            if b'MZ' in h[:2]:
                # A. DOT NET (Check for BSJB metadata or mscoree)
                if b'BSJB' in h or b'mscorlib' in h or b'mscoree.dll' in h: 
                    return "DOT_NET"
                
                # B. PYTHON (STRICT FIX: Removed 'MEI')
                # Only trust strong strings that definitely indicate Python
                if b'pyi-windows-manifest' in h or b'PyInstaller' in h: 
                    return "PYTHON"
                
                # If we see "python3.dll" AND it's not just a text string in a Native app
                if b'python' in h and b'libpython' in h:
                    return "PYTHON"

                # C. NATIVE (Default)
                return "NATIVE"
            
            # 3. LINUX
            if b'ELF' in h: return "NATIVE"
            
        except: pass
        return "UNKNOWN"

    def process_pyc(self, pyc):
        final = None
        if os.path.exists(TOOL_PYCDC):
            try:
                res = subprocess.run([TOOL_PYCDC, pyc], capture_output=True, text=True, timeout=5)
                if res.stdout and "def " in res.stdout: final = res.stdout
            except: pass
        if not final: final = MagicPatcher.try_patch(pyc)
        if not final:
            try:
                with open(pyc, 'rb') as f: data = f.read(); code_obj = marshal.loads(data[16:])
                final = StackDecompilerV2(code_obj).decompile()
            except: pass
        full = OmniscientEngine.generate_full_view(pyc, final or "# FAIL")
        with open(pyc.replace(".pyc", ".py"), "w", encoding="utf-8") as f: f.write(full)

class PentestGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VU CodeShield v1.3")
        self.resize(1500, 950)
        self.setAcceptDrops(True)
        if os.path.exists(LOGO_PATH): self.setWindowIcon(QIcon(LOGO_PATH))
        self.initUI()

    def initUI(self):
        self.setStyleSheet(STYLES)
        w = QWidget(); self.setCentralWidget(w); l = QVBoxLayout(); w.setLayout(l); l.setContentsMargins(0,0,0,0)
        h = QFrame(); h.setObjectName("Header"); h.setFixedHeight(80); hl = QHBoxLayout(); hl.setContentsMargins(20, 10, 20, 10)
        if os.path.exists(LOGO_PATH):
            lbl = QLabel(); px = QPixmap(LOGO_PATH); lbl.setPixmap(px.scaled(60, 60, Qt.KeepAspectRatio, Qt.SmoothTransformation)); hl.addWidget(lbl); hl.addSpacing(15)
        v = QVBoxLayout(); t = QLabel("VU CodeShield"); t.setObjectName("Title"); v.addWidget(t)
        s = QLabel("VAPT SUITE"); s.setObjectName("Subtitle"); v.addWidget(s)
        hl.addLayout(v); hl.addStretch()
        self.pill = QLabel(" READY "); self.pill.setStyleSheet("border: 2px solid #C0392B; color: #C0392B; border-radius: 4px; padding: 6px 12px; font-weight: bold; font-family: 'Consolas';"); hl.addWidget(self.pill)
        h.setLayout(hl); l.addWidget(h)
        
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("QTabBar::tab { height: 35px; width: 150px; font-weight: bold; } QTabBar::tab:selected { color: #C0392B; }")
        
        tab1 = QWidget(); t1 = QHBoxLayout(); tab1.setLayout(t1)
        self.log = QTextEdit(); self.log.setReadOnly(True)
        self.tree = QTreeWidget(); self.tree.setHeaderLabels(["File Name", "Type"]); self.tree.setColumnWidth(0, 500)
        self.tree.itemDoubleClicked.connect(self.open_item)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu); self.tree.customContextMenuRequested.connect(self.menu)
        spl = QSplitter(Qt.Horizontal); spl.addWidget(self.log); spl.addWidget(self.tree); spl.setSizes([400, 1000])
        t1.addWidget(spl)
        
        tab2 = QWidget(); t2 = QVBoxLayout(); tab2.setLayout(t2)
        self.vuln_table = QTableWidget(); self.vuln_table.setColumnCount(4); self.vuln_table.setHorizontalHeaderLabels(["SEVERITY", "VULNERABILITY", "FILE", "MATCH DETAILS"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        t2.addWidget(self.vuln_table)
        
        self.tabs.addTab(tab1, "📂 SOURCE FILES"); self.tabs.addTab(tab2, "🛡️ THREAT INTEL")
        l.addWidget(self.tabs)
        self.prog = QProgressBar(); self.prog.setTextVisible(False); self.prog.setRange(0, 100); l.addWidget(self.prog)

    def dragEnterEvent(self, e): e.accept()
    def dropEvent(self, e): self.start([u.toLocalFile() for u in e.mimeData().urls()][0])
    def start(self, path):
        self.log.clear(); self.tree.clear(); self.vuln_table.setRowCount(0); self.prog.setValue(0); self.pill.setText(" PROCESSING ")
        self.th = DecompilerThread(path)
        self.th.log_signal.connect(self.log.append); self.th.status_signal.connect(self.pill.setText); 
        self.th.progress_signal.connect(self.prog.setValue)
        self.th.pulse_signal.connect(self.toggle_pulse)
        self.th.finished_signal.connect(self.done); self.th.start()

    def toggle_pulse(self, active):
        if active: self.prog.setRange(0, 0)
        else: self.prog.setRange(0, 100)

    def done(self, path, findings):
        self.prog.setRange(0, 100); self.prog.setValue(100); self.pill.setText(" COMPLETE "); self.populate_tree(path); self.populate_vulns(findings)
        if findings: self.tabs.setCurrentIndex(1)
    def populate_tree(self, path):
        root = QTreeWidgetItem(self.tree); root.setText(0, os.path.basename(path)); root.setExpanded(True); self.add_rec(root, path)
    def add_rec(self, p, path):
        try:
            for e in os.scandir(path):
                if e.name.endswith(('.dll','.png','.ico')): continue
                i = QTreeWidgetItem(p); i.setText(0, e.name); i.setData(0, Qt.UserRole, e.path)
                if e.name.endswith(".cs"): i.setText(1, "C# SOURCE"); i.setForeground(1, QColor("#4F27AE"))
                elif e.name.endswith(".py"): i.setText(1, "PYTHON SOURCE"); i.setForeground(1, QColor("#27AE60"))
                elif e.name.endswith((".c", ".cpp")): i.setText(1, "NATIVE C"); i.setForeground(1, QColor("#8E44AD"))
                if e.is_dir(): self.add_rec(i, e.path)
        except: pass
    def populate_vulns(self, findings):
        self.vuln_table.setRowCount(len(findings))
        for r, f in enumerate(findings):
            sev = QTableWidgetItem(f['severity']); sev.setTextAlignment(Qt.AlignCenter)
            if f['severity'] == "CRITICAL": sev.setBackground(QBrush(QColor("#C0392B"))); sev.setForeground(QBrush(QColor("white")))
            elif f['severity'] == "HIGH": sev.setBackground(QBrush(QColor("#E67E22"))); sev.setForeground(QBrush(QColor("white")))
            else: sev.setBackground(QBrush(QColor("#F1C40F")))
            self.vuln_table.setItem(r, 0, sev); self.vuln_table.setItem(r, 1, QTableWidgetItem(f['name'])); self.vuln_table.setItem(r, 2, QTableWidgetItem(f['file'])); self.vuln_table.setItem(r, 3, QTableWidgetItem(f['matches']))
    def menu(self, pos):
        sel = self.tree.selectedItems()
        if sel: m = QMenu(); a = QAction(f"BUNDLE FILES", self); a.triggered.connect(lambda: self.bundle(sel)); m.addAction(a); m.exec_(self.tree.viewport().mapToGlobal(pos))
    def bundle(self, items):
        p = os.path.join(os.path.dirname(items[0].data(0, Qt.UserRole)), "BUNDLE.txt")
        c = "Analysis Bundle:\n\n"; 
        for i in items:
            with open(i.data(0, Qt.UserRole), "r", errors='ignore') as f: c += f"--- {i.text(0)} ---\n{f.read()}\n\n"
        with open(p, "w", encoding="utf-8") as f: f.write(c); os.startfile(p)
    def open_item(self, i): 
        p = i.data(0, Qt.UserRole)
        if p and os.path.exists(p) and not os.path.isdir(p): os.startfile(p)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    app = QApplication(sys.argv)
    window = PentestGUI()
    window.show()
    sys.exit(app.exec_())
