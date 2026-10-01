#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Эмпирический свип RTX 5060 8GB: VRAM/темп/скорость vs размер контекста."""
import json, os, time, subprocess, urllib.request, re

CFG = r"C:/Users/Wizzer/.lmstudio/apps/bionic/.internal/user-concrete-model-default-config/fairy322/Huihui-Qwen3.5-9B-Claude-4.6-Opus-abliterated-heretic-GGUF/Huihui-Qwen3.5-9B-Claude-4.6-Opus-abliterated-heretic.Q4_K_S.gguf.json"
BASE = "http://127.0.0.1:1234/v1"
KEY = "huihui-qwen3.5-9b-claude-4.6-opus-abliterated-heretic"
OP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
OUT = r"C:/Users/Wizzer/AppData/Local/Temp/ebm_sweep.json"

PROMPT = "Составь нумерованный список из 25 пунктов по уходу за газоном летом. Каждый пункт — одно короткое предложение."

def set_ctx(ctx):
    d = json.load(open(CFG, encoding="utf-8"))
    for f in d["load"]["fields"]:
        if f["key"] == "llm.load.contextLength":
            f["value"] = ctx
    json.dump(d, open(CFG, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

def kill_engine():
    subprocess.run(["powershell","-NoProfile","-Command",
        "Get-Process llama-server -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep 3"],
        capture_output=True)
    time.sleep(1)

def gpu():
    try:
        o = subprocess.run(["nvidia-smi","--query-gpu=memory.used,memory.total,temperature.gpu,power.draw,utilization.gpu",
                            "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=20).stdout.strip()
        p = [x.strip() for x in o.split(",")]
        return {"vram_used_mb": int(p[0]), "vram_total_mb": int(p[1]), "temp_c": int(p[2]),
                "power_w": float(p[3]), "util_pct": int(p[4])}
    except Exception as e:
        return {"error": str(e)}

def gen(max_tokens=300):
    body = {"model": KEY, "messages": [{"role":"user","content":PROMPT}],
            "temperature": 0.1, "max_tokens": max_tokens, "stream": False}
    req = urllib.request.Request(BASE+"/chat/completions",
        data=json.dumps(body).encode(), headers={"Content-Type":"application/json"})
    t0 = time.time()
    with OP.open(req, timeout=600) as r:
        j = json.loads(r.read())
    dt = time.time() - t0
    u = j.get("usage", {})
    ct = u.get("completion_tokens", 0)
    return {"wall_s": round(dt,2), "completion_tokens": ct,
            "tok_s": round(ct/dt,1) if dt>0 else 0,
            "content_len": len(j["choices"][0]["message"].get("content") or "")}

res = []
for ctx in [2048, 4096, 8192, 16384]:
    set_ctx(ctx)
    kill_engine()
    time.sleep(2)
    g_before = gpu()
    try:
        gen(5)                 # прогрев: JIT-загрузка модели вне замера
        time.sleep(0.5)
        r = gen()              # измеряемый прогон на уже загруженной модели
    except Exception as e:
        r = {"error": str(e)}
    time.sleep(1)
    g_after = gpu()
    row = {"ctx": ctx, "load_vram_mb": g_before.get("vram_used_mb"),
           "run": r, "gpu_after": g_after}
    res.append(row)
    print(f"ctx={ctx:6d} | VRAM={g_after.get('vram_used_mb')}MB | temp={g_after.get('temp_c')}C | "
          f"{r.get('tok_s','ERR')} tok/s | {r.get('wall_s','')}s | {r.get('completion_tokens','')} tok")
    json.dump(res, open(OUT,"w",encoding="utf-8"), ensure_ascii=False, indent=1)

print("\nSAVED", OUT)
