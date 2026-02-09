import os
import shutil
import subprocess
import time
import sys
import marshal
import traceback
from PyQt5.QtCore import QThread, pyqtSignal
from Config import (WORKSPACE_DIR, TOOL_ILSPY_EXE, TOOL_ILSPY_DLL, TOOL_JADX, 
                   TOOL_EXTRACTOR, TOOL_PYCDC)
from Engines import (GhidraEngine, AdvancedSanitizer, VulnerabilityScanner, 
                    ReportGenerator, MagicPatcher, StackDecompilerV2)

class DecompilerThread(QThread):
    log_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    pulse_signal = pyqtSignal(bool)
    finished_signal = pyqtSignal(str, list)
    
    def __init__(self, input_file): 
        super().__init__()
        self.original_input = input_file
        self.processed_files = set()
        self.queue = []
        self.findings = []
    
    def log(self, msg): self.log_signal.emit(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def run(self):
        try:
            self.status_signal.emit("INITIALIZING")
            self.progress_signal.emit(0)
            
            clean_name = os.path.splitext(os.path.basename(self.original_input))[0].replace(" ", "_")
            case_dir = os.path.join(WORKSPACE_DIR, f"CASE_{int(time.time())}_{clean_name}")
            self.src_root = os.path.join(case_dir, "RECOVERED_SOURCE")
            os.makedirs(self.src_root, exist_ok=True)
            
            self.queue.append(self.original_input)
            
            while self.queue:
                current_target = self.queue.pop(0)
                if current_target in self.processed_files: continue
                self.processed_files.add(current_target)
                self.process_single_binary(current_target, self.src_root)

            self.status_signal.emit("VULN SCANNING")
            self.log("🛡️ Scanning for Vulnerabilities...")
            self.run_vapt_scan(self.src_root)

            self.status_signal.emit("COMPLETE")
            self.progress_signal.emit(100)
            self.finished_signal.emit(self.src_root, self.findings)
        except Exception as e:
            self.log(f"CRITICAL ERROR: {e}")
            self.log(traceback.format_exc())
            self.status_signal.emit("ERROR")

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
        
        elif ftype == "JAVA":
            self.status_signal.emit(f"JAVA : {fname}")
            subprocess.run([TOOL_JADX, "-d", sub_out, "--deobf", "-j", "4", target_path], stdout=subprocess.DEVNULL)
        
        elif ftype == "PYTHON":
            self.status_signal.emit(f"PYTHON : {fname}")
            # Simplified PyInstaller extraction logic
            target_copy = os.path.join(sub_out, fname)
            shutil.copy2(target_path, target_copy)
            subprocess.run([sys.executable, TOOL_EXTRACTOR, target_copy], cwd=sub_out, stdout=subprocess.DEVNULL)
            # Find pyc files and decompile
            for root, dirs, files in os.walk(sub_out):
                for file in files:
                    if file.endswith(".pyc"): self.decompile_pyc(os.path.join(root, file))

        elif ftype == "NATIVE":
            if os.path.getsize(target_path) > 50 * 1024: # > 50KB
                self.status_signal.emit(f"NATIVE : {fname}")
                self.pulse_signal.emit(True)
                ghidra = GhidraEngine(self.log_signal, self.status_signal)
                ghidra.run(target_path, sub_out)
                self.pulse_signal.emit(False)

    def decompile_pyc(self, pyc_path):
        final_code = None
        # Try PyCDC
        if os.path.exists(TOOL_PYCDC):
            try:
                res = subprocess.run([TOOL_PYCDC, pyc_path], capture_output=True, text=True, timeout=5)
                if res.stdout and "def " in res.stdout: final_code = res.stdout
            except: pass
        # Fallback to Header Patching
        if not final_code: final_code = MagicPatcher.try_patch(pyc_path)
        
        # Save Result
        if final_code:
            with open(pyc_path.replace(".pyc", ".py"), "w", encoding="utf-8") as f: f.write(final_code)

    def run_vapt_scan(self, root_folder):
        total_files = sum([len(files) for r, d, files in os.walk(root_folder)])
        scanned = 0
        for root, dirs, files in os.walk(root_folder):
            for file in files:
                if file.endswith(('.cs', '.java', '.py', '.c', '.cpp', '.xml', '.json')):
                    scanned += 1
                    if total_files > 0: self.progress_signal.emit(int((scanned/total_files)*100))
                    try:
                        fpath = os.path.join(root, file)
                        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                            hits = VulnerabilityScanner.scan_file(fpath, f.read())
                            if hits: self.findings.extend(hits)
                    except: pass
        ReportGenerator.generate_html(os.path.dirname(root_folder), self.findings)

    def detect_sig(self, path):
        try:
            with open(path, 'rb') as f: h = f.read(4096)
            if h.startswith(b'\xCA\xFE\xBA\xBE') or path.endswith(('.jar', '.war')): return "JAVA"
            if b'MZ' in h[:2]:
                if b'BSJB' in h or b'mscorlib' in h: return "DOT_NET"
                if b'PyInstaller' in h: return "PYTHON"
                return "NATIVE"
            if b'ELF' in h: return "NATIVE"
        except: pass
        return "UNKNOWN"