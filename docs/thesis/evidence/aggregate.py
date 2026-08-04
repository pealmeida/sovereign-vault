#!/usr/bin/env python3
"""Agregador da execução definitiva — EXECUCAO-DEFINITIVA.md §5 e §6.

Lê os CSVs por sessão em ``target/thesis-eval/sessions/sNN/`` e produz, em
``docs/thesis/evidence/``:

* ``latency-aggregated.csv``     — média das médias de sessão + IC 95% por
  *bootstrap* percentílico (10.000 reamostragens) sobre as k médias de sessão
  (§5.1–§5.2). A unidade independente é a sessão; tirar IC sobre iterações
  dentro de uma sessão seria pseudorreplicação.
* ``micro-aggregated.csv``       — mesmo desenho, para as medições isoladas
  (decifra e filtro) de ``micro.csv``.
* ``adversarial-aggregated.csv`` — taxa de bloqueio como proporção sobre
  k × n_sondas, com IC exato de Wilson de 95% (§5.3; *bootstrap* é inadequado
  para proporção binária com n pequeno). Sondas marcadas ``transport_error``
  não produziram veredito do servidor e são excluídas do numerador **e** do
  denominador de ambas as taxas, sendo reportadas à parte: falha de transporte
  é ruído de infraestrutura, não decisão de política.

Qualificação de tamanho de amostra: com ``k`` no piso declarado (3), o IC 95%
percentílico é determinado praticamente pelo triplo (mínimo, mediano, máximo)
das médias de sessão — cobertura pobre e amplitude instável. O IC nessa
fronteira é **indicativo**, e a legenda da tese deve dizê-lo; ``k>=5``
(desenho da execução definitiva) é o alvo prático. Pelo mesmo motivo, o teste
de deriva de Spearman (§6.2) só é aplicado com ``k>=4``: com 3 pontos sem
empate, ``|rho|`` é sempre 1 e o limiar dispararia em toda célula, refletindo o
tamanho de amostra e não deriva real.

Também verifica o critério de aceitação da própria execução (§6):
CV entre sessões por célula (§6.1), deriva monotônica por Spearman (§6.2),
concordância das sondas adversariais entre sessões (§6.3) e integridade dos
arquivos por sessão (§6.5). Nenhuma sessão ou iteração é descartada pelo
script (§5.4): divergências são reportadas, nunca corrigidas.

Somente biblioteca padrão — cumpre incondicionalmente a ressalva do §5.2 de
não depender de numpy/scipy e de não recorrer à aproximação normal.

Uso:
    python3 docs/thesis/evidence/aggregate.py [sessions_dir] [out_dir]

Padrões: sessions_dir=target/thesis-eval/sessions, out_dir=docs/thesis/evidence.
Código de saída: 0 = aceito; 1 = falha estrutural (<3 sessões, arquivo
ausente); 2 = aceito com ressalvas (CV ou deriva fora do critério).
"""

import csv
import json
import math
import random
import sys
from pathlib import Path

B = 10_000          # reamostragens de bootstrap (§2.1)
RNG_SEED = 20260606  # semente declarada do gerador (§5.2)
Z_95 = 1.959_963_984_540_054  # quantil 0,975 da normal padrão (Wilson, §5.3)
MIN_SESSIONS = 3    # régua declarada: k >= 3 (§5.2); trava anti-execução acidental
TARGET_SESSIONS = 5  # alvo prático do desenho definitivo; abaixo disso o IC é indicativo
CV_OK = 0.10        # §6.1: aceitável
CV_MAX = 0.20       # §6.1: limítrofe; acima, inaceitável
SPEARMAN_MAX = 0.8  # §6.2: |rho| acima indica deriva monotônica
SPEARMAN_MIN_K = 4  # §6.2 só é informativo com k >= 4 (ver docstring)

# §6.5: campos de host cuja ausência torna a proveniência inútil.
REQUIRED_HOST_FIELDS = ("os", "kernel", "cpu_model", "cpu_cores", "ram_kb", "power_mode")
UNUSABLE_VALUES = ("", "n/a", "N/A", "unknown")

STAGES = ("validate", "authorize", "execute", "filter", "total")
MICRO_COMPONENTS = ("decrypt", "filter")


def boot_ci(values, rng):
    """Média e IC 95% percentílico por bootstrap sobre as médias de sessão."""
    n = len(values)
    means = sorted(
        sum(rng.choices(values, k=n)) / n for _ in range(B)
    )
    # Percentis 2,5 e 97,5 com interpolação linear (mesma convenção do
    # numpy.percentile default), aplicada sobre as B médias reamostradas.
    def percentile(sorted_vals, q):
        pos = q * (len(sorted_vals) - 1)
        lo = int(pos)
        frac = pos - lo
        if lo + 1 >= len(sorted_vals):
            return sorted_vals[-1]
        return sorted_vals[lo] * (1.0 - frac) + sorted_vals[lo + 1] * frac

    return (
        sum(values) / n,
        percentile(means, 0.025),
        percentile(means, 0.975),
    )


def wilson_ci(successes, trials):
    """IC exato de Wilson de 95% para uma proporção binária (§5.3)."""
    if trials == 0:
        return (0.0, 0.0, 0.0)
    p = successes / trials
    z2 = Z_95 * Z_95
    denom = 1.0 + z2 / trials
    center = (p + z2 / (2.0 * trials)) / denom
    half = (
        Z_95
        / denom
        * math.sqrt(p * (1.0 - p) / trials + z2 / (4.0 * trials * trials))
    )
    return (p, max(0.0, center - half), min(1.0, center + half))


def ranks(values):
    """Rangs 1..n com média em empates (para Spearman)."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    out = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for t in range(i, j + 1):
            out[order[t]] = avg
        i = j + 1
    return out


def spearman(xs, ys):
    """Correlação de Spearman = Pearson sobre os rangs."""
    rx, ry = ranks(xs), ranks(ys)
    n = len(rx)
    mx, my = sum(rx) / n, sum(ry) / n
    cov = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    vx = sum((a - mx) ** 2 for a in rx)
    vy = sum((b - my) ** 2 for b in ry)
    if vx == 0.0 or vy == 0.0:
        return 0.0
    return cov / math.sqrt(vx * vy)


def drift(values):
    """Spearman contra a ordem das sessões, ou ``None`` se k < SPEARMAN_MIN_K.

    Com k=3 e sem empates, |rho| é sempre 1: o teste diria "deriva" em toda
    célula, medindo o tamanho da amostra e não o fenômeno (§6.2).
    """
    if len(values) < SPEARMAN_MIN_K:
        return None
    return spearman(list(range(len(values))), values)


def cv(values):
    """Coeficiente de variação amostral (ddof=1) das médias de sessão."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    if mean == 0.0:
        return 0.0
    var = sum((v - mean) ** 2 for v in values) / (n - 1)
    return math.sqrt(var) / mean


def load_sessions(sessions_dir):
    sessions = sorted(p for p in sessions_dir.iterdir() if p.is_dir())
    if len(sessions) < MIN_SESSIONS:
        sys.exit(
            f"erro: {len(sessions)} sessão(ões) em {sessions_dir}; "
            f"mínimo {MIN_SESSIONS} (§5.2)"
        )
    return sessions


def check_integrity(sessions):
    """§6.5: cada sessão deve ter os três CSVs + run-metadata.json preenchido.

    A existência do ``run-metadata.json`` não basta: campos de host em ``n/a``
    ou com placeholder passam pela checagem de existência e produzem
    proveniência inútil (ou falsa). São rejeitados aqui.
    """
    problems = []
    for s in sessions:
        for name in ("latency.csv", "micro.csv", "adversarial.csv"):
            path = s / name
            if not path.exists():
                problems.append(f"{s.name}: {name} ausente")
            elif sum(1 for _ in path.open(encoding="utf-8")) < 2:
                problems.append(f"{s.name}: {name} truncado (só cabeçalho)")
        meta_path = s / "run-metadata.json"
        if not meta_path.exists():
            problems.append(f"{s.name}: run-metadata.json ausente (§3)")
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            problems.append(f"{s.name}: run-metadata.json ilegível ({exc})")
            continue
        host = meta.get("host", {})
        for field in REQUIRED_HOST_FIELDS:
            value = str(host.get(field, "")).strip()
            if value in UNUSABLE_VALUES:
                problems.append(
                    f"{s.name}: host.{field}='{value or 'ausente'}' — "
                    "preencher antes de agregar (§3)"
                )
            elif "PLACEHOLDER" in value.upper() or "FIXAR" in value.upper():
                problems.append(
                    f"{s.name}: host.{field} contém placeholder '{value}' — "
                    "proveniência falsa (§3)"
                )
        rustc = str(meta.get("toolchain", {}).get("rustc", "")).strip()
        if rustc in UNUSABLE_VALUES:
            problems.append(f"{s.name}: toolchain.rustc ausente ou 'n/a' (§3)")
    return problems


def aggregate_latency(sessions, rng):
    """§5.1–§5.2: média das médias de sessão + bootstrap, por célula/estágio."""
    cells = {}
    for s in sessions:
        with (s / "latency.csv").open(encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                key = (row["mode"], int(row["bytes"]), row["stage"])
                cells.setdefault(key, []).append(float(row["mean_us"]))

    rows = []
    acceptance = []
    for (mode, size, stage), vals in sorted(cells.items()):
        if len(vals) < MIN_SESSIONS:
            sys.exit(
                f"erro: célula ({mode},{size},{stage}) tem {len(vals)} "
                f"sessões; mínimo {MIN_SESSIONS} (§5.2)"
            )
        mean, lo, hi = boot_ci(vals, rng)
        rows.append((mode, size, stage, len(vals), mean, lo, hi))
        acceptance.append((mode, size, stage, cv(vals), drift(vals)))
    return rows, acceptance


def aggregate_micro(sessions, rng):
    """Mesmo desenho do §5.2 aplicado às médias isoladas de micro.csv."""
    cells = {}
    for s in sessions:
        with (s / "micro.csv").open(encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                size = int(row["bytes"])
                cells.setdefault((size, "decrypt"), []).append(
                    float(row["decrypt_mean_us"])
                )
                cells.setdefault((size, "filter"), []).append(
                    float(row["filter_mean_us"])
                )

    rows = []
    acceptance = []
    for (size, component), vals in sorted(cells.items()):
        if len(vals) < MIN_SESSIONS:
            sys.exit(
                f"erro: célula micro ({size},{component}) tem {len(vals)} "
                f"sessões; mínimo {MIN_SESSIONS} (§5.2)"
            )
        mean, lo, hi = boot_ci(vals, rng)
        rows.append((size, component, len(vals), mean, lo, hi))
        acceptance.append(("micro", size, component, cv(vals), drift(vals)))
    return rows, acceptance


def aggregate_adversarial(sessions):
    """§5.3: proporção sobre k × n_sondas com IC de Wilson; §6.3 concordância.

    Observações com ``transport_error=True`` não carregam decisão de política e
    são excluídas de ambas as taxas, contadas à parte. CSVs anteriores à coluna
    ``transport_error`` são lidos como se não houvesse nenhuma.
    """
    per_probe = {}
    transport_errors = 0
    for s in sessions:
        with (s / "adversarial.csv").open(encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                if row.get("transport_error", "False") == "True":
                    transport_errors += 1
                    continue
                per_probe.setdefault(row["id"], []).append(
                    (row["class"], row["blocked"] == "True")
                )

    divergent = []
    totals = {"attack": [0, 0], "control": [0, 0]}  # classe: [sucessos, tentativas]
    for probe_id, observations in sorted(per_probe.items()):
        klass = observations[0][0]
        verdicts = {blocked for _, blocked in observations}
        if len(verdicts) > 1:
            divergent.append(probe_id)
        if klass == "attack":
            # Sucesso do controle = sonda bloqueada.
            totals["attack"][0] += sum(1 for _, b in observations if b)
            totals["attack"][1] += len(observations)
        else:
            # Sucesso do controle = sonda legítima aceita (disponibilidade).
            totals["control"][0] += sum(1 for _, b in observations if not b)
            totals["control"][1] += len(observations)

    rows = []
    for klass in ("attack", "control"):
        successes, trials = totals[klass]
        rate, lo, hi = wilson_ci(successes, trials)
        rows.append((klass, len(sessions), trials, successes, rate, lo, hi))
    return rows, divergent, transport_errors


def main():
    sessions_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("target/thesis-eval/sessions")
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("docs/thesis/evidence")
    if not sessions_dir.is_dir():
        sys.exit(f"erro: diretório de sessões inexistente: {sessions_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)

    sessions = load_sessions(sessions_dir)
    problems = check_integrity(sessions)
    if problems:
        for p in problems:
            print(f"INTEGRIDADE FALHOU (§6.5): {p}")
        sys.exit(1)
    print(f"{len(sessions)} sessões íntegras em {sessions_dir}")

    rng = random.Random(RNG_SEED)

    lat_rows, lat_acc = aggregate_latency(sessions, rng)
    mic_rows, mic_acc = aggregate_micro(sessions, rng)
    adv_rows, adv_divergent, adv_transport_errors = aggregate_adversarial(sessions)

    with (out_dir / "latency-aggregated.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["mode", "bytes", "stage", "k_sessions", "mean_us", "ci95_lo", "ci95_hi"])
        for mode, size, stage, k, mean, lo, hi in lat_rows:
            w.writerow([mode, size, stage, k, f"{mean:.3f}", f"{lo:.3f}", f"{hi:.3f}"])

    with (out_dir / "micro-aggregated.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["bytes", "component", "k_sessions", "mean_us", "ci95_lo", "ci95_hi"])
        for size, component, k, mean, lo, hi in mic_rows:
            w.writerow([size, component, k, f"{mean:.3f}", f"{lo:.3f}", f"{hi:.3f}"])

    with (out_dir / "adversarial-aggregated.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["class", "k_sessions", "n_trials", "n_success", "rate", "ci95_lo", "ci95_hi"])
        for klass, k, trials, successes, rate, lo, hi in adv_rows:
            w.writerow([klass, k, trials, successes, f"{rate:.4f}", f"{lo:.4f}", f"{hi:.4f}"])

    print(f"latency-aggregated.csv: {len(lat_rows)} linhas")
    print(f"micro-aggregated.csv: {len(mic_rows)} linhas")
    print(f"adversarial-aggregated.csv: {len(adv_rows)} linhas")
    for klass, k, trials, successes, rate, lo, hi in adv_rows:
        label = "bloqueio" if klass == "attack" else "disponibilidade"
        print(
            f"  {klass}: taxa de {label} {successes}/{trials} "
            f"({rate * 100:.1f}%), IC Wilson 95% [{lo * 100:.1f}, {hi * 100:.1f}]"
        )
    print(f"  sondas excluídas por erro de transporte: {adv_transport_errors}")

    # --- Critério de aceitação (§6): reporta; nunca descarta (§5.4). ---
    reservations = []
    k = len(sessions)
    if k < TARGET_SESSIONS:
        reservations.append(
            f"§5.2 k={k} < {TARGET_SESSIONS}: o IC 95% por bootstrap é indicativo "
            "nesta fronteira (determinado pelos extremos das médias de sessão); "
            "declarar a qualificação na legenda da tabela"
        )
    if k < SPEARMAN_MIN_K:
        reservations.append(
            f"§6.2 k={k} < {SPEARMAN_MIN_K}: teste de deriva de Spearman não aplicado "
            "(|rho| seria 1 por construção); deriva não foi verificada"
        )
    if adv_transport_errors:
        reservations.append(
            f"§5.3 {adv_transport_errors} observação(ões) de sonda com erro de "
            "transporte, excluídas de ambas as taxas: investigar a infraestrutura "
            "antes de reportar as taxas como estáveis"
        )
    for mode, size, stage, cell_cv, cell_drift in lat_acc + mic_acc:
        cell = f"({mode},{size},{stage})"
        if cell_cv > CV_MAX:
            reservations.append(f"§6.1 CV={cell_cv:.1%} > 20% em {cell}: inaceitável sem investigação")
        elif cell_cv > CV_OK:
            reservations.append(f"§6.1 CV={cell_cv:.1%} em (10%,20%] em {cell}: sinalizar na legenda")
        if cell_drift is not None and abs(cell_drift) > SPEARMAN_MAX:
            reservations.append(
                f"§6.2 Spearman rho={cell_drift:.2f} em {cell}: deriva monotônica; "
                "exigir reinício entre sessões e refazer"
            )
    for probe_id in adv_divergent:
        reservations.append(
            f"§6.3 sonda {probe_id} diverge entre sessões: investigar "
            "não-determinismo antes de reportar"
        )

    manifest = {
        "sessions": [s.name for s in sessions],
        "bootstrap_resamples": B,
        "bootstrap_seed": RNG_SEED,
        "ci_method_latency": "percentile bootstrap over session means",
        "ci_method_adversarial": "Wilson score interval",
        "adversarial_transport_errors_excluded": adv_transport_errors,
        "drift_test_applied": k >= SPEARMAN_MIN_K,
        "ci_indicative_only": k < TARGET_SESSIONS,
        "reservations": reservations,
    }
    with (out_dir / "aggregate-metadata.json").open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")

    if reservations:
        print("\nACEITO COM RESSALVAS — resolver antes de atualizar a tese (§7):")
        for r in reservations:
            print(f"  - {r}")
        sys.exit(2)
    print("\nCritério de aceitação (§6) satisfeito: CV <= 10%, sem deriva, sondas concordantes.")


if __name__ == "__main__":
    main()
