import os
import re
import sys
import shutil
import subprocess
import dis
import marshal
import io
import types
import time
from Config import VULN_DB, GHIDRA_RAM_LIMIT, GHIDRA_CPU_LIMIT, TOOL_GHIDRA_HEADLESS, TOOL_PYCDC, WORKSPACE_DIR

# ==============================================================================
#  ANALYSIS ENGINES
# ==============================================================================

class VulnerabilityScanner:
    @staticmethod
    def scan_file(filepath, content):
        findings = []
        for sig in VULN_DB:
            try:
                matches = re.findall(sig['regex'], content, re.IGNORECASE)
                if matches:
                    # Clean up matches to avoid massive strings
                    unique = list(set([str(m)[:50] for m in matches]))[:5]
                    findings.append({ 
                        "severity": sig['severity'], 
                        "name": sig['name'], 
                        "desc": sig['desc'], 
                        "file": os.path.basename(filepath), 
                        "matches": str(unique), 
                        "path": filepath 
                    })
            except: pass
        return findings

class ReportGenerator:
    @staticmethod
    def generate_html(case_dir, findings):
        ts = int(time.time())
        report_path = os.path.join(case_dir, f"VULN_REPORT_{ts}.html")
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings: 
            sev = f.get('severity', "LOW")
            stats[sev] = stats.get(sev, 0) + 1
            
        html = f"""<html><head><title>VU CodeShield Report</title>
        <style>body{{font-family: 'Segoe UI', Arial; background:#F5F7FA; padding:20px; color:#333;}}
        h1{{color:#C0392B; border-bottom: 2px solid #C0392B; padding-bottom:10px;}}
        .summary{{display:flex; gap:20px; margin-bottom:30px;}} 
        .card{{background:white; padding:15px; border-radius:8px; width:150px; text-align:center; box-shadow:0 2px 5px rgba(0,0,0,0.1);}}
        .crit{{border-top:5px solid #C0392B; color:#C0392B; font-weight:bold; font-size:20px;}} 
        .high{{border-top:5px solid #E67E22; color:#E67E22; font-weight:bold; font-size:20px;}}
        table{{width:100%; border-collapse:collapse; background:white; box-shadow:0 2px 5px rgba(0,0,0,0.05);}} 
        th,td{{padding:12px; text-align:left; border-bottom:1px solid #ddd;}} 
        th{{background:#2C3E50; color:white;}} tr:hover{{background-color:#f1f1f1;}}
        code{{background:#eee; padding:2px 5px; border-radius:3px; color:#D35400;}}
        </style></head><body>
        <h1>🛡️ VAPT REPORT</h1>
        <p><b>Target:</b> {os.path.basename(case_dir)} | <b>Date:</b> {time.ctime()}</p>
        <div class="summary">
            <div class="card crit">CRITICAL<br>{stats['CRITICAL']}</div>
            <div class="card high">HIGH<br>{stats['HIGH']}</div>
            <div class="card">MEDIUM<br>{stats['MEDIUM']}</div>
        </div>
        <table><tr><th>SEVERITY</th><th>ISSUE</th><th>FILE</th><th>EVIDENCE</th></tr>"""
        
        for f in findings: 
            html += f"<tr><td><b>{f['severity']}</b></td><td>{f['name']}</td><td>{f['file']}</td><td><code>{f['matches']}...</code></td></tr>"
        html += "</table></body></html>"
        
        with open(report_path, "w", encoding="utf-8") as f: f.write(html)
        return report_path

class StructureBooster:
    @staticmethod
    def boost(code):
        lines = []
        ptr_pattern = re.compile(r'\*\s*\(\w+\s*\*\)\s*\(([\w_]+)\s*\+\s*(0x[\da-f]+)\)')
        for line in code.splitlines():
            match = ptr_pattern.search(line)
            if match:
                var, offset = match.group(1), match.group(2)
                line = line.replace(match.group(0), f"{var}->field_{offset}")
            lines.append(line)
        return "\n".join(lines)

class AdvancedSanitizer:
    @staticmethod
    def clean_file(filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f: code = f.read()
            code = code.replace("undefined4", "int").replace("undefined2", "short").replace("undefined1", "byte")
            code = code.replace("uint", "unsigned int").replace("ushort", "unsigned short")
            code = StructureBooster.boost(code)
            with open(filepath, "w", encoding="utf-8") as f: f.write(code)
            return True
        except: return False

    @staticmethod
    def clean(source_code):
        return re.sub(r"NULL\s*\|\s*self\s*\+\s*", "self.", source_code)

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

class StackDecompilerV2:
    def __init__(self, code_obj, indent_level=0):
        self.co = code_obj; self.output = []; self.indent_level = indent_level
    def indent(self): return "    " * self.indent_level
    def decompile(self):
        try:
            instructions = list(dis.get_instructions(self.co))
            self.output.append(f"{self.indent()}# Partial Recovery of {self.co.co_name}")
            for instr in instructions:
                if "LOAD_CONST" in instr.opname: self.output.append(f"{self.indent()}val = {repr(instr.argval)}")
                elif "STORE_NAME" in instr.opname: self.output.append(f"{self.indent()}{instr.argrepr} = val")
                elif "CALL_FUNCTION" in instr.opname: self.output.append(f"{self.indent()}func(...)")
        except: pass
        return "\n".join(self.output)

class GhidraEngine:
    def __init__(self, log_signal, status_signal):
        self.log_signal = log_signal; self.status_signal = status_signal
    
    def run(self, target_path, output_dir):
        if not os.path.exists(TOOL_GHIDRA_HEADLESS):
            self.log_signal.emit(f"❌ Ghidra Headless not found at: {TOOL_GHIDRA_HEADLESS}"); return
        
        self.log_signal.emit("🚀 Launching GHIDRA C/C++ ENGINE (Turbo Mode)...")
        self.log_signal.emit(f"⚙️ Config: RAM={GHIDRA_RAM_LIMIT} | CPU={GHIDRA_CPU_LIMIT}")
        
        # 1. Script: Force Minimal Analysis then Decompile
        script_content = """
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.flatapi import FlatProgramAPI

args = getScriptArgs()
if len(args) > 0:
    out_dir = args[0]
    if not os.path.exists(out_dir): os.makedirs(out_dir)
    
    program = currentProgram
    monitor = ConsoleTaskMonitor()
    api = FlatProgramAPI(program)
    
    print("VU-LOG: [+] Binary Loaded. Starting Fast Analysis...")
    
    # FORCE BASIC ANALYSIS
    api.analyzeChanges(program) 
    
    decomplib = DecompInterface()
    decomplib.openProgram(program)
    
    iterator = program.getListing().getFunctions(True)
    count = 0
    
    print("VU-LOG: [+] Extraction started...")
    
    while iterator.hasNext():
        func = iterator.next()
        count += 1
        
        if count % 10 == 0: 
            print("VU-LOG: Processing Function #" + str(count) + " (" + func.getName() + ")")
        
        try:
            res = decomplib.decompileFunction(func, 5, monitor)
            if res.decompileCompleted():
                c_code = res.getDecompiledFunction().getC()
                fname = func.getName()
                safe_name = "".join([c for c in fname if c.isalnum() or c in '_'])
                if not safe_name: safe_name = "func_" + str(count)
                
                with open(os.path.join(out_dir, safe_name + ".c"), "w") as f:
                    f.write("// RECOVERED: " + fname + "\\n" + c_code)
        except: pass

    print("VU-LOG: [+] Extraction Complete.")
"""
        script_path = os.path.join(WORKSPACE_DIR, "ghidra_export.py")
        
        # FIX: Explicitly use UTF-8 to avoid Windows charmap errors
        with open(script_path, "w", encoding="utf-8") as f: f.write(script_content)
        
        # 2. Command
        proj_path = os.path.join(WORKSPACE_DIR, "Ghidra_Proj")
        proj_name = f"P_{int(time.time())}"
        if not os.path.exists(proj_path): os.makedirs(proj_path)
        
        cmd = [
            TOOL_GHIDRA_HEADLESS, 
            proj_path, 
            proj_name, 
            "-import", target_path,
            "-noanalysis",                  
            "-analysisTimeoutPerFile", "300",
            "-postScript", script_path, output_dir, 
            "-deleteProject"
        ]
        
        # 3. Execution
        try:
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True, 
                bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
                encoding="utf-8", # Ensure we read the output as UTF-8 too
                errors="replace"  # Ignore weird characters from Ghidra console
            )
            
            for line in process.stdout:
                line = line.strip()
                if not line: continue
                if "VU-LOG:" in line:
                    self.log_signal.emit(f"⚙️ {line.split('VU-LOG:')[-1].strip()}")
                elif "ERROR" in line:
                    self.log_signal.emit(f"⚠️ {line}")
            
            process.wait()
            self.log_signal.emit("✅ Ghidra Process Finished.")
        except Exception as e: 
            self.log_signal.emit(f"❌ Error: {e}")