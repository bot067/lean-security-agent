#!/usr/bin/env python3
"""
Security Agent Orchestrator v2.1 — Angular Security Module
- Статический анализ Angular (rg + angular-rules.json)
- Динамический анализ (XSS, PP, Template Injection, Open Redirect)
- Клиент к Bionic Studio (OpenAI API)
- Парсер <tool_call> / JSON block / bare JSON
- Валидатор команд по белому списку
- Smart Pruner + Finding Aggregator (4096 токенов)
"""
import json, re, os, sys, subprocess as sp
from datetime import datetime
from pathlib import Path
from typing import Optional
from collections import deque

# ─── Конфиг ─────────────────────────────────────────────────
LLM_API_URL = "http://127.0.0.1:1234/v1/chat/completions"
LLM_MODEL = "huihui-qwen3.5-9b-claude-4.6-opus-abliterated-heretic"

MAX_CONTEXT_TOKENS = 4096
MAX_STDOUT_CHARS = 800
MAX_STDERR_CHARS = 200
MAX_PRUNE_LINES = 100
DRY_RUN = False

ALLOWED_COMMANDS = {"nmap","curl","ffuf","jq","grep","cat","ls","echo","rg","head","tail","wc","sort","uniq","cut"}
BLOCKED_PATTERNS = [r"-rf\b", r"\bsh\b", r"\bbash\b", r"\|\|", r";;", r"`", r"\$\(", r">\s*/dev/"]
REPORTS_DIR = Path("./agent_reports")
RULES_PATH = Path(__file__).parent / "angular-rules.json"
PAYLOADS_PATH = Path(__file__).parent / "angular-payloads.json"

MAX_ITERATIONS = 50
MAX_LOOP_REPEATS = 3
MAX_FINDINGS = 10

# ─── Angular Assets ────────────────────────────────────────
ANGULAR_RULES = []
ANGULAR_PAYLOADS = {}
def load_assets():
    global ANGULAR_RULES, ANGULAR_PAYLOADS
    if RULES_PATH.exists():
        with open(RULES_PATH) as f:
            ANGULAR_RULES = json.load(f).get("rules", [])
    if PAYLOADS_PATH.exists():
        with open(PAYLOADS_PATH) as f:
            ANGULAR_PAYLOADS = json.load(f).get("payloads", {})
load_assets()

# ─── Framework Registry (dynamic loading) ─────────────────
FRAMEWORK_REGISTRY = {
    "angular2": {"rules": ["/app/rules/angular2-rules.json"], "g_extensions": ["*.ts","*.html"]},
    "angularjs": {"rules": ["/app/rules/angularjs-rules.json"], "g_extensions": ["*.js","*.ts","*.html"]},
    "react":   {"rules": ["/app/rules/react-rules.json"],   "g_extensions": ["*.tsx","*.jsx","*.ts"]},
    "vue":     {"rules": ["/app/rules/vue-rules.json"],     "g_extensions": ["*.vue","*.ts"]},
    "svelte":  {"rules": ["/app/rules/svelte-rules.json"],  "g_extensions": ["*.svelte","*.ts"]},
}

ACTIVE_FRAMEWORK = "angular2"  # default

def load_framework_assets(framework: str = "angular2"):
    """Load rules & payloads for a given framework from container paths."""
    global ANGULAR_RULES, ANGULAR_PAYLOADS, ACTIVE_FRAMEWORK
    entry = FRAMEWORK_REGISTRY.get(framework, FRAMEWORK_REGISTRY["angular2"])
    ACTIVE_FRAMEWORK = framework
    rules_paths = entry["rules"]

    # Try loading from host files (for orchestrator-side use)
    all_rules = []
    for rp in rules_paths:
        # Из пути /app/rules/angularjs-rules.json извлекаем имя файла
        basename = os.path.basename(rp)
        local_path = Path(__file__).parent / basename
        if local_path.exists():
            with open(local_path) as f:
                all_rules.extend(json.load(f).get("rules", []))
    ANGULAR_RULES.clear()
    ANGULAR_RULES.extend(all_rules or [])

    # Payloads: generic (framework-independent) + framework-specific
    payload_local = Path(__file__).parent / (framework + "-payloads.json")
    if payload_local.exists():
        with open(payload_local) as f:
            loaded = json.load(f).get("payloads", {})
            ANGULAR_PAYLOADS.clear()
            ANGULAR_PAYLOADS.update(loaded)

    log(f"Loaded {len(ANGULAR_RULES)} rules, {len(ANGULAR_PAYLOADS)} payload categories for '{framework}'")
    return ACTIVE_FRAMEWORK

def auto_detect_framework(target_url: str = "http://172.20.0.10:3000") -> str:
    """Probe target for framework fingerprints via curl headers + body."""
    import urllib.request
    argv = ["curl", "-s", target_url, "--connect-timeout", "5"]
    try:
        body = sp.run(["docker", "exec", "security-agent"] + argv, capture_output=True, text=True, timeout=10).stdout.lower()
    except:
        return "angular2"

    # Angular 2+ (modern): ng-version attribute, ES bundles
    if "ng-version" in body or "main-es" in body or "polyfills-es" in body or "runtime-es" in body:
        return "angular2"
    # AngularJS (legacy): polyfills.js + main.js pattern
    if "polyfills.js" in body and ("main.js" in body or "angular" in body):
        return "angularjs"

    # React: react root, next.js, create-react-app
    if any(m in body for m in ["react-root", "_next", "__next_data", "react-dom", "create-react-app"]):
        return "react"
    # Nuxt/Vue: __nuxt, vue.js, vuex
    if any(m in body for m in ["__nuxt", "vue.js", "vuex", "v-html", "v-bind"]):
        return "vue"
    # Svelte: __svelte, svelte element markers
    if any(m in body for m in ["__svelte", "svelte-", "sveltekit"]):
        return "svelte"

    return "angular2"  # default

def get_framework_g_extensions(framework: str = None) -> list:
    return FRAMEWORK_REGISTRY.get(framework or ACTIVE_FRAMEWORK, FRAMEWORK_REGISTRY["angular2"])["g_extensions"]
SYSTEM_PROMPT = """You are a security testing agent inside an isolated Docker container.

TARGET: Juice Shop at 172.20.0.10:3000 (Node.js + Angular web app)

KNOWN VULNERABILITY TYPES:
- DOM XSS (bypassSecurityTrust*, [innerHTML])
- Client-Side Prototype Pollution (deep merge of untrusted data)
- Angular Template Injection (JIT compilation)
- Open Redirect / Path Traversal
- Insecure Client-Side Storage (localStorage JWT)
- SQL/NoSQL Injection, JWT issues, BOLA, file upload bypass

YOUR TOOLS:
1. run_command — execute any allowed binary (curl, ffuf, rg, nmap, etc.)
2. static_analysis — run rg rules against source code
3. dynamic_analysis — run payloads against live target

STATIC ANALYSIS (rg against source):
  docker exec security-agent rg --json -g '*.ts' -g '*.html' 'bypassSecurityTrustHtml' /app/workspace/src/

DYNAMIC ANALYSIS (curl against target):
  curl -X POST http://172.20.0.10:3000/ -d 'input=<img src=x onerror=alert(1)>'

RULES:
- tool MUST be "run_command"
- argv is a JSON array of strings
- timeout_seconds max = 120
- Keep responses short — use Smart Pruner output
- Report findings: [FINDING] vector | target | evidence
- Do NOT repeat the same command more than twice"""

# ─── Logging ──────────────────────────────────────────────
def log(msg: str, level: str = "INFO"):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [{level}] {msg}", file=sys.stderr)

# ─── LLM Client ───────────────────────────────────────────
def query_llm(messages: list, temperature: float = 0.05, max_tokens: int = 1024) -> Optional[dict]:
    import urllib.request, urllib.error
    for k in ['http_proxy','https_proxy','HTTP_PROXY','HTTPS_PROXY']:
        os.environ.pop(k, None)
    payload = json.dumps({"model":LLM_MODEL,"messages":messages,"temperature":temperature,"max_tokens":max_tokens}).encode()
    try:
        resp = urllib.request.urlopen(urllib.request.Request(LLM_API_URL, data=payload, headers={"Content-Type":"application/json"}, method="POST"), timeout=180)
        return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        log(f"LLM HTTP {e.code}: {e.read().decode()[:200]}", "ERROR")
        return None
    except Exception as e:
        log(f"LLM error: {e}", "ERROR")
        return None

def extract_content(response: dict) -> str:
    try: return response["choices"][0]["message"]["content"] or ""
    except: return ""

def extract_usage(response: dict) -> dict:
    try: return response["usage"]
    except: return {}

# ─── Tool Call Parser ─────────────────────────────────────
TOOL_CALL_RE = re.compile(r'<tool_call>(.*?)</tool_call>', re.DOTALL)
JSON_BLOCK_RE = re.compile(r'```(?:json)?\s*\n?(\{.*?\})\n?```', re.DOTALL)
BARE_JSON_RE = re.compile(r'\{\"tool\":\s*\"run_command\".*?\"argv\":\s*\[.*?\].*?\}', re.DOTALL)

def parse_tool_call(text: str) -> Optional[dict]:
    m = TOOL_CALL_RE.search(text) or JSON_BLOCK_RE.search(text) or BARE_JSON_RE.search(text)
    if not m: return None
    try: cmd = json.loads(m.group(1).strip())
    except: return None
    if not isinstance(cmd, dict): return None
    t = cmd.get("tool","")
    if t != "run_command" and t in ALLOWED_COMMANDS:
        log(f"Fixing tool: '{t}' -> 'run_command'", "WARN")
        cmd["tool"] = "run_command"
    if cmd.get("tool") != "run_command": return None
    argv = cmd.get("argv",[])
    if not isinstance(argv, list) or not argv: return None
    return {"argv": argv, "timeout": cmd.get("timeout_seconds", 30)}

# ─── Command Validator ────────────────────────────────────
def validate_command(argv: list) -> tuple:
    t = argv[0] if argv else ""
    if t not in ALLOWED_COMMANDS: return False, f"Command '{t}' not allowed"
    full = " ".join(argv)
    for p in BLOCKED_PATTERNS:
        if re.search(p, full): return False, f"Blocked pattern '{p}'"
    return True, "OK"

# ─── Angular Static Analysis ──────────────────────────────
def run_static_analysis(rules: list = None, target_dir: str = "/app/workspace/src") -> list:
    """Run rg-based static analysis. Uses active framework extensions."""
    findings = []
    g_exts = get_framework_g_extensions()
    for rule in (rules or ANGULAR_RULES):
        rid = rule.get("id","?"); sev = rule.get("severity","MEDIUM"); pat = rule.get("rg_pattern","")
        if not pat: continue
        argv = ["rg","--json"] + [flag for ext in g_exts for flag in ("-g", ext)] + [pat, target_dir]
        v, reason = validate_command(argv)
        if not v: log(f"Rule '{rid}' skipped: {reason}", "WARN"); continue
        try:
            r = sp.run(["docker","exec","security-agent"]+argv, capture_output=True, text=True, timeout=30)
            for line in r.stdout.strip().split('\n'):
                if not line: continue
                try: e = json.loads(line)
                except: continue
                if e.get("type") == "match":
                    d = e.get("data",{})
                    findings.append({
                        "rule_id": rid, "severity": sev,
                        "file": f"{d.get('path',{}).get('text','?')}:{d.get('line_number',0)}",
                        "snippet": d.get("lines",{}).get("text","").strip()[:120],
                        "description": rule.get("description",""),
                        "remediation": rule.get("remediation",""),
                        "vector": rid.split("_")[0] if "_" in rid else "?"
                    })
        except Exception as ex:
            log(f"rg failed for '{rid}': {ex}", "WARN")
    log(f"Static analysis ({ACTIVE_FRAMEWORK}): {len(findings)} findings from {len(ANGULAR_RULES)} rules")
    return findings

# ─── Dynamic Analysis ─────────────────────────────────────
def run_dynamic_xss(payloads: list = None, target_url: str = "http://172.20.0.10:3000") -> list:
    findings = []
    for pl in (payloads or (ANGULAR_PAYLOADS.get("dom_xss",{}).get("entries",[])))[:10]:
        safe = pl.replace("'","\\'")
        argv = ["curl","-s","-o","/dev/null","-w","%{http_code}",target_url,"-d",f"input={safe}"]
        if not validate_command(argv)[0]: continue
        try: code = sp.run(["docker","exec","security-agent"]+argv, capture_output=True, text=True, timeout=15).stdout.strip()
        except: continue
        argv2 = ["curl","-s",target_url,"-d",f"input={safe}"]
        try: body = sp.run(["docker","exec","security-agent"]+argv2, capture_output=True, text=True, timeout=15).stdout
        except: body = ""
        if pl in body:
            findings.append({"vector":"DOM_XSS","severity":"CRITICAL","payload":pl[:80],"http_code":code,"reflected":True,"endpoint":target_url})
            log(f"XSS REFLECTED: {pl[:50]}...", "WARN")
    return findings

def run_dynamic_headers(target_url: str = "http://172.20.0.10:3000") -> list:
    findings = []
    argv = ["curl","-sI",target_url]
    if not validate_command(argv)[0]: return findings
    try: hdrs = sp.run(["docker","exec","security-agent"]+argv, capture_output=True, text=True, timeout=15).stdout
    except: return findings
    checks = [("X-Content-Type-Options","nosniff","Missing nosniff"),("X-Frame-Options","DENY|SAMEORIGIN","Missing XFO"),("Content-Security-Policy","","Missing CSP")]
    for h,_,msg in checks:
        if h not in hdrs: findings.append({"vector":"HEADERS","severity":"MEDIUM","header":h,"issue":msg,"endpoint":target_url})
    if "Set-Cookie" in hdrs:
        for sc in [l for l in hdrs.split('\n') if 'Set-Cookie' in l]:
            miss = [f for f in ["HttpOnly","SameSite"] if f not in sc]
            if miss: findings.append({"vector":"STORAGE","severity":"MEDIUM","header":sc.strip()[:80],"issue":f"Missing: {','.join(miss)}","endpoint":target_url})
    return findings

def run_pp_scan(target_url: str = "http://172.20.0.10:3000") -> list:
    findings = []
    for pp in ['{"__proto__":{"polluted":"true"}}','{"constructor":{"prototype":{"polluted":"true"}}}']:
        argv = ["curl","-s","-o","/dev/null","-w","%{http_code}",target_url,"-H","Content-Type: application/json","-d",pp]
        if not validate_command(argv)[0]: continue
        try: code = sp.run(["docker","exec","security-agent"]+argv, capture_output=True, text=True, timeout=15).stdout.strip()
        except: continue
        findings.append({"vector":"PROTOTYPE_POLLUTION","severity":"HIGH","payload":pp[:60],"http_code":code,"endpoint":target_url})
    return findings

# ─── Smart Pruner ─────────────────────────────────────────
def smart_prune(result: dict) -> str:
    stdout = result.get("stdout",""); stderr = result.get("stderr","")
    code = result.get("exit_code",0); log_path = result.get("log_path","")
    lines = stdout.split('\n')
    if len(lines) > MAX_PRUNE_LINES:
        stdout = '\n'.join(lines[:50]) + f"\n... [{len(lines)} lines total] ...\n" + '\n'.join(lines[-50:])
    elif len(stdout) > MAX_STDOUT_CHARS:
        stdout = stdout[:MAX_STDOUT_CHARS] + f"\n... (truncated {len(stdout)} chars)"
    if len(stderr) > MAX_STDERR_CHARS:
        stderr = stderr[-MAX_STDERR_CHARS:]
    meta = f"\n[Log: {log_path}]" if log_path else ""
    return f"<tool_output status=\"{code}\">\nstdout:\n{stdout}\nstderr:\n{stderr}{meta}\n</tool_output>"

# ─── Finding Aggregator (Smart Pruner for 4096 ctx) ──────
FINDING_PATTERNS = [
    (r"SQL\s*injection","SQL Injection"), (r"XSS|bypassSecurityTrust","DOM XSS"),
    (r"JWT|JsonWebToken","JWT Issue"), (r"BOLA|Broken\s*Object","Broken Object Level Authorization"),
    (r"NoSQL","NoSQL Injection"), (r"401|403","Access Control Issue"),
    (r"directory\s*listing|Directory","Directory Listing"), (r"CORS","CORS Misconfiguration"),
    (r"open\s*redirect|OpenRedirect|returnUrl","Open Redirect"),
    (r"file\s*upload","File Upload Bypass"), (r"prototype|__proto__|pollution","Prototype Pollution"),
    (r"template\s*injection|compileModule|CompilerFactory","Angular Template Injection"),
    (r"localStorage|sessionStorage","Insecure Client-Side Storage"),
    (r"innerHTML|nativeElement|document\.write","DOM Manipulation XSS"),
]

def extract_findings(text: str, output: str) -> list:
    combined = (text + " " + output).lower()
    return [name for pat,name in FINDING_PATTERNS if re.search(pat, combined)]

def smart_prune_findings(findings: list, max_tokens: int = MAX_CONTEXT_TOKENS) -> str:
    """Aggregate findings into compact format fitting 4096-token LLM context.
    Output: file_path:line | severity | rule_id | snippet[:60]"""
    if not findings:
        return "<findings count=\"0\">No vulnerabilities detected.</findings>"
    seen = set(); unique = []
    for f in findings:
        key = f"{f.get('file','')}|{f.get('rule_id','')}"
        if key not in seen:
            seen.add(key); unique.append(f)
    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    unique.sort(key=lambda x: sev_order.get(x.get("severity",""),99))
    lines = [f"{f.get('file','?')} | {f.get('severity','?')} | {f.get('rule_id','?')} | {f.get('snippet','?')[:60]}" for f in unique]
    header = f"<findings count=\"{len(unique)}\" raw=\"{len(findings)}\">"
    body = "\n".join(lines)
    full = f"{header}\n{body}\n</findings>"
    if len(full)//4 > max_tokens//2:
        body = "\n".join(lines[:MAX_FINDINGS]) + f"\n... [{len(lines)-MAX_FINDINGS} more findings truncated]"
        full = f"{header}\n{body}\n</findings>"
    return full

# ─── Command Executor ─────────────────────────────────────
def execute_command(argv: list, timeout: int = 30) -> dict:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = REPORTS_DIR / f"raw_{ts}.log"
    docker_argv = ["docker", "exec", "security-agent"] + argv
    try:
        result = sp.run(docker_argv, capture_output=True, text=True, timeout=timeout)
        stdout, stderr, code = result.stdout, result.stderr, result.returncode
    except sp.TimeoutExpired:
        stdout, stderr, code = "", f"TIMEOUT {timeout}s", -1
    except FileNotFoundError:
        stdout, stderr, code = "", "Docker not found", -2
    except Exception as e:
        stdout, stderr, code = "", str(e), -3
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w") as f:
        f.write(f"Command: {' '.join(docker_argv)}\nExit: {code}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n")
    return {"stdout": stdout, "stderr": stderr, "exit_code": code, "log_path": str(log_path)}

# ─── Token Estimation & History Trimmer ──────────────────
def estimate_tokens(text: str) -> int:
    return len(text) // 4

def trim_history(messages: list, max_tokens: int = MAX_CONTEXT_TOKENS) -> list:
    if estimate_tokens(json.dumps(messages)) <= max_tokens:
        return messages
    trimmed, tool_count = [], 0
    for m in messages:
        if m.get("role") == "tool":
            tool_count += 1
            trimmed.append({"role": "tool", "content": f"[Tool executed. Count: {tool_count}. Log saved.]"})
        else:
            trimmed.append(m)
    while len(trimmed) > 2 and estimate_tokens(json.dumps(trimmed)) > max_tokens:
        trimmed.pop(1)
    return trimmed

# ─── Loop Detector ────────────────────────────────────────
def detect_loop(cmd_history: deque) -> bool:
    if len(cmd_history) < MAX_LOOP_REPEATS:
        return False
    return len(set(map(tuple, list(cmd_history)[-MAX_LOOP_REPEATS:]))) == 1

# ─── Main Loop ────────────────────────────────────────────
def main():
    log("Security Agent Orchestrator v2.1 — Angular Module ready")
    log(f"Model: {LLM_MODEL}")
    log(f"Angular rules loaded: {len(ANGULAR_RULES)} | Payloads: {len(ANGULAR_PAYLOADS)}")

    task = input("Enter task for security agent (or 'exit'): ").strip()
    if not task or task.lower() == "exit":
        return

    # Auto-detect or manual framework selection
    if "--fw" in task:
        fw = task.split("--fw")[1].split()[0].strip().lower()
        load_framework_assets(fw)
        log(f"Manual framework: {fw}", "INFO")
    else:
        fw = auto_detect_framework()
        load_framework_assets(fw)
        log(f"Auto-detected framework: {fw}", "INFO")

    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": task}]
    step = 0
    total_tokens = 0
    findings = set()
    cmd_history = deque(maxlen=MAX_LOOP_REPEATS)
    findings_count = 0

    if any(kw in task.lower() for kw in ["static", "rg ", "angular-rules", "source"]):
        log("Static analysis mode triggered", "INFO")
        sa_findings = run_static_analysis()
        findings_str = smart_prune_findings(sa_findings)
        for f in sa_findings:
            fname = f"STATIC:{f.get('vector','?')}({f.get('severity','?')})"
            if fname not in findings:
                findings.add(fname)
                findings_count = len(findings)
                log(f"FINDING: {fname} | {f.get('file','?')} | {f.get('snippet','?')[:50]}", "WARN")
        print(f"\n=== STATIC ANALYSIS RESULTS ===\n{findings_str}\n=== END ===")

    while step < MAX_ITERATIONS:
        step += 1
        if detect_loop(cmd_history):
            log(f"LOOP DETECTED: same cmd {MAX_LOOP_REPEATS}x. Stopping.", "WARN")
            break
        if findings_count >= MAX_FINDINGS:
            log(f"MAX FINDINGS ({MAX_FINDINGS}) reached.", "INFO")
            break
        if step % 5 == 0:
            pct = estimate_tokens(json.dumps(messages)) / MAX_CONTEXT_TOKENS * 100
            log(f"[METRIC] Iter {step}/{MAX_ITERATIONS} | Tokens: {total_tokens} | Findings: {findings_count} | Context: {pct:.0f}%")

        messages = trim_history(messages)
        response = query_llm(messages)
        content = extract_content(response)
        usage = extract_usage(response)
        total_tokens += usage.get("total_tokens", 0)

        if not content:
            log("Empty response, aborting", "ERROR")
            break

        cmd = parse_tool_call(content)
        if not cmd:
            log("No valid tool_call, asking regenerate")
            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "user", "content": "No valid tool_call. Output EXACTLY: {\"tool\": \"run_command\", \"argv\": [...], \"timeout_seconds\": N}"})
            continue

        argv = cmd["argv"]
        cmd_history.append(tuple(argv))
        valid, reason = validate_command(argv)
        if not valid:
            log(f"Rejected: {reason}", "WARN")
            result = {"stdout": "", "stderr": f"REJECTED: {reason}", "exit_code": -1, "log_path": ""}
        else:
            log(f"Exec: {' '.join(argv)}")
            result = execute_command(argv, cmd["timeout"])

        tool_output = smart_prune(result)
        for f in extract_findings(content, result.get("stdout", "")):
            if f not in findings:
                findings.add(f)
                findings_count = len(findings)
                log(f"FINDING: {f}", "WARN")

        messages.append({"role": "assistant", "content": content})
        messages.append({"role": "tool", "content": tool_output})
        log(f"Exit: {result['exit_code']} | Output: {len(result.get('stdout',''))} chars")

    print(f"\n{'='*60}\nSESSION COMPLETE\n{'='*60}")
    print(f"Iterations:    {step}")
    print(f"Tokens used:   {total_tokens}")
    print(f"Findings:      {findings_count}")
    if findings:
        print("Found:")
        for f in sorted(findings):
            print(f"  {f}")
    print(f"{'='*60}\n")
    log("Session ended")

if __name__ == "__main__":
    main()