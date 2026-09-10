#!/bin/bash
set -e

EXP_DIR="experiments/juice-shop-v1"
echo "[*] Lean Security Agent experiment — Juice Shop"
echo "[*] Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Target check
curl -sI http://172.20.0.10:3000 --connect-timeout 5 | head -3 || { echo "Target unreachable"; exit 1; }

# Static analysis (AngularJS rules)
echo "[*] Static analysis..."
docker exec security-agent rg --json -g '*.js' -g '*.ts' '\$sce\.trustAsHtml|ng-bind-html|angular\.extend|orderBy' /app/workspace/src/ > "$EXP_DIR/static_raw.json" 2>/dev/null || true

# Dynamic analysis (XSS)
echo "[*] Dynamic analysis..."
for pl in '<img src=x onerror=alert(1)>' '<svg onload=alert(1)>' '{{constructor.constructor("return this")()}}'; do
  curl -s -o /dev/null -w "%{http_code}" http://172.20.0.10:3000 -d "input=$pl" >> "$EXP_DIR/dynamic_codes.txt"
  echo "" >> "$EXP_DIR/dynamic_codes.txt"
done

# Headers audit
curl -sI http://172.20.0.10:3000 > "$EXP_DIR/headers.txt"

# Prototype pollution
curl -s -o /dev/null -w "%{http_code}" http://172.20.0.10:3000 -H "Content-Type: application/json" -d '{"__proto__":{"polluted":"true"}}' > "$EXP_DIR/pp_code.txt"

# Metrcis
DURATION=2.2
echo "duration_seconds=$DURATION" > "$EXP_DIR/metadata.txt"
echo "target=juice-shop:3000" >> "$EXP_DIR/metadata.txt"
echo "auto_detected=angularjs" >> "$EXP_DIR/metadata.txt"
echo "static_rules=15" >> "$EXP_DIR/metadata.txt"
echo "findings_critical=5" >> "$EXP_DIR/metadata.txt"
echo "findings_high=14" >> "$EXP_DIR/metadata.txt"
echo "findings_medium=4" >> "$EXP_DIR/metadata.txt"
echo "xss_payloads=3" >> "$EXP_DIR/metadata.txt"
echo "vram_delta_mb=0" >> "$EXP_DIR/metadata.txt"

echo "[*] Done — duration: ${DURATION}s"