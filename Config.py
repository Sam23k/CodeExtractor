import os
import sys

# ==============================================================================
#  GLOBAL CONFIGURATION & PORTABLE PATHS
# ==============================================================================

# Dynamic Base Path (Where this script is running)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(BASE_DIR, "Tools")
WORKSPACE_DIR = os.path.join(BASE_DIR, "Workspace")
ICON_PATH = os.path.join(BASE_DIR, "icon.png")

# Ensure Workspace Exists
if not os.path.exists(WORKSPACE_DIR):
    os.makedirs(WORKSPACE_DIR)

# --- HELPER: SMART TOOL FINDER ---
def find_ghidra():
    """Automatically finds Ghidra analyzeHeadless.bat regardless of folder version name"""
    target = "analyzeHeadless.bat" if os.name == 'nt' else "analyzeHeadless"
    
    # 1. Check strict path
    strict_path = os.path.join(TOOLS_DIR, "ghidra", "support", target)
    if os.path.exists(strict_path): return strict_path
    
    # 2. Search for versioned folders (e.g., ghidra_11.0_PUBLIC)
    if os.path.exists(TOOLS_DIR):
        for folder in os.listdir(TOOLS_DIR):
            if folder.lower().startswith("ghidra") and os.path.isdir(os.path.join(TOOLS_DIR, folder)):
                candidate = os.path.join(TOOLS_DIR, folder, "support", target)
                if os.path.exists(candidate):
                    return candidate
    return "GHIDRA_NOT_FOUND"

# EXTERNAL TOOL PATHS
TOOL_EXTRACTOR = os.path.join(TOOLS_DIR, "pyinstxtractor", "pyinstxtractor.py")
TOOL_JADX = os.path.join(TOOLS_DIR, "jadx", "bin", "jadx.bat" if os.name == 'nt' else "jadx")
TOOL_PYCDC = os.path.join(TOOLS_DIR, "pycdc", "pycdc.exe" if os.name == 'nt' else "pycdc")
TOOL_ILSPY_EXE = os.path.join(TOOLS_DIR, "ilspy", "ilspycmd.exe")
TOOL_ILSPY_DLL = os.path.join(TOOLS_DIR, "ilspy", "ilspycmd.dll")

# Dynamic Ghidra Path
# HARDCODED PATH (Since we know exactly where it is)
TOOL_GHIDRA_HEADLESS = r"C:\Users\PC\Desktop\RE_Arsenal\Tools\ghidra\support\analyzeHeadless.bat"

# SYSTEM LIMITS
GHIDRA_RAM_LIMIT = "16G"
GHIDRA_CPU_LIMIT = "6"

# UI STYLES
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

# ==============================================================================
#  ADVANCED VULNERABILITY DATABASE
# ==============================================================================
VULN_DB = [
    # --- CLOUD SECRETS ---
    {"name": "AWS Access Key", "regex": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "severity": "CRITICAL", "desc": "Hardcoded AWS Credential"},
    {"name": "Google API Key", "regex": r"AIza[0-9A-Za-z\\-_]{35}", "severity": "CRITICAL", "desc": "Hardcoded Google Cloud API Key"},
    {"name": "Slack Token", "regex": r"xox[baprs]-([0-9a-zA-Z]{10,48})", "severity": "CRITICAL", "desc": "Hardcoded Slack Bot/User Token"},
    {"name": "Stripe API Key", "regex": r"sk_live_[0-9a-zA-Z]{24}", "severity": "CRITICAL", "desc": "Stripe Live Payment Key"},
    {"name": "Private Key", "regex": r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----", "severity": "CRITICAL", "desc": "Embedded Cryptographic Private Key"},
    
    # --- CREDENTIALS ---
    {"name": "Hardcoded Password", "regex": r"(password|passwd|pwd|secret|api_key|auth_token)\s*=\s*['\"](?![A-Z0-9_]+\()(.*?)['\"]", "severity": "HIGH", "desc": "Possible hardcoded credential string"},
    {"name": "Authorization Header", "regex": r"Authorization:\s*Bearer\s+[a-zA-Z0-9\-\._~\+\/]+", "severity": "HIGH", "desc": "Hardcoded Bearer Token"},
    
    # --- DANGEROUS CODE ---
    {"name": "Command Injection", "regex": r"(os\.system|subprocess\.call|subprocess\.Popen|Runtime\.getRuntime\(\)\.exec|system\()", "severity": "HIGH", "desc": "Execution of OS commands"},
    {"name": "Unsafe Deserialization", "regex": r"(pickle\.loads|Marshal\.load|ObjectInputStream|yaml\.load\()", "severity": "HIGH", "desc": "Potential RCE via deserialization"},
    {"name": "SQL Injection", "regex": r"(execute|executeQuery)\s*\(\s*['\"].*?%s.*?['\"]", "severity": "HIGH", "desc": "Potential SQL Injection via string formatting"},
    {"name": "Dangerous C Function", "regex": r"\b(strcpy|strcat|sprintf|gets)\s*\(", "severity": "MEDIUM", "desc": "Potential Buffer Overflow vulnerability"},
    
    # --- NETWORK & INFO LEAK ---
    {"name": "Internal IP Address", "regex": r"\b192\.168\.\d{1,3}\.\d{1,3}\b|\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "severity": "MEDIUM", "desc": "Hardcoded Internal IP"},
    {"name": "Hardcoded Email", "regex": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "severity": "LOW", "desc": "PII or Internal Email Leak"},
    {"name": "Insecure HTTP", "regex": r"http://", "severity": "MEDIUM", "desc": "Unencrypted communication protocol"},
]