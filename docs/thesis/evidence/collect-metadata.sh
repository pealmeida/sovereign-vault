#!/usr/bin/env bash
# Uso: collect-metadata.sh <sessions_dir> <session_id> <eval_tag> <power_mode> <command_line...>
#
# <power_mode> é obrigatório e descreve o perfil de energia efetivamente
# aplicado à sessão (ex.: "AC-alto-desempenho", "AC-balanceado"). Não há valor
# padrão: um placeholder gravado no run-metadata.json seria proveniência falsa
# (EXECUCAO-DEFINITIVA.md §3).
set -euo pipefail

if [ "$#" -lt 5 ]; then
  echo "uso: $0 <sessions_dir> <session_id> <eval_tag> <power_mode> <command_line...>" >&2
  exit 2
fi

OUT_DIR="$1"; SESSION_ID="$2"; EVAL_TAG="$3"; POWER_MODE="$4"; shift 4
COMMAND="$*"

if [ -z "${POWER_MODE// }" ]; then
  echo "erro: power_mode vazio; informe o perfil de energia da sessão (§3)" >&2
  exit 2
fi

SESSION_DIR="$OUT_DIR/sessions/$SESSION_ID"
mkdir -p "$SESSION_DIR"

META="$SESSION_DIR/run-metadata.json"

# Plataforma-agnóstico o possível: tenta /proc (Linux), depois WMIC/PowerShell
# (Windows, disponível sob Git Bash). Só cai em "n/a" se nenhuma fonte existir —
# e aggregate.py rejeita "n/a" nos campos de host (§6.5), de modo que um
# ambiente não coberto falha em vez de produzir metadados inúteis.
win_ps() { powershell.exe -NoProfile -NonInteractive -Command "$1" 2>/dev/null | tr -d '\r' | head -1; }

KERNEL=$(uname -r 2>/dev/null || echo "n/a")
OS=$(uname -s 2>/dev/null || echo "n/a")
if [ -r /proc/cpuinfo ]; then
  CPU_MODEL=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//')
else
  CPU_MODEL=$(win_ps '(Get-CimInstance Win32_Processor).Name')
fi
CPU_CORES=$(nproc 2>/dev/null || win_ps '(Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors')
if [ -r /proc/meminfo ]; then
  RAM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
else
  RAM_KB=$(win_ps '[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1KB)')
fi
STORAGE=$(df -h "$OUT_DIR" 2>/dev/null | tail -1 | awk '{print $1" "$2" "$4" free"}' || echo "n/a")
RUSTC=$(rustc --version 2>/dev/null || echo "n/a")

# No Windows, `uname` sob Git Bash reporta MINGW/MSYS; registra também a build
# do sistema, que é o valor com significado de reprodutibilidade.
case "$OS" in
  MINGW*|MSYS*|CYGWIN*)
    WIN_BUILD=$(win_ps '(Get-CimInstance Win32_OperatingSystem).Caption + " build " + (Get-CimInstance Win32_OperatingSystem).BuildNumber')
    [ -n "$WIN_BUILD" ] && { OS="$WIN_BUILD"; KERNEL="$WIN_BUILD"; }
    ;;
esac

for field in OS KERNEL CPU_MODEL CPU_CORES RAM_KB RUSTC; do
  value="${!field}"
  if [ -z "${value// }" ] || [ "$value" = "n/a" ]; then
    echo "erro: campo de host '$field' não pôde ser coletado neste ambiente;" >&2
    echo "      preencha manualmente antes de agregar — aggregate.py rejeita 'n/a' (§6.5)" >&2
    exit 3
  fi
done

cat > "$META" <<EOF
{
  "session_id": "$SESSION_ID",
  "eval_tag": "$EVAL_TAG",
  "commit": "$(git rev-parse HEAD)",
  "command": "$COMMAND",
  "profile": "release",
  "date_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": {
    "os": "$OS",
    "kernel": "$KERNEL",
    "cpu_model": "$CPU_MODEL",
    "cpu_cores": "$CPU_CORES",
    "ram_kb": "$RAM_KB",
    "storage": "$STORAGE",
    "power_mode": "$POWER_MODE"
  },
  "toolchain": {
    "rustc": "$RUSTC"
  }
}
EOF

echo "metadata -> $META"
