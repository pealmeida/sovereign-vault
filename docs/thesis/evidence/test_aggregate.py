#!/usr/bin/env python3
"""Testes de regressão do agregador de evidência (§5–§6).

Executar: ``python docs/thesis/evidence/test_aggregate.py``

O agregador transforma CSVs de sessão nos números que vão para o Capítulo 4.
Um erro de contagem aqui não levanta exceção nem produz saída implausível: ele
publica um número errado. Estes testes fixam os invariantes que não podem
regredir silenciosamente.
"""
import importlib.util
import json
import random
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("aggregate", HERE / "aggregate.py")
agg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agg)

LATENCY = (
    "mode,bytes,iterations,stage,mean_us,p50_us,p95_us\n"
    "direct,128,1000,total,100,95,140\n"
)
MICRO = (
    "bytes,decrypt_mean_us,decrypt_p95_us,filter_mean_us,filter_p95_us\n"
    "128,50,70,5,9\n"
)


def write_session(root, sid, adversarial, meta_override=None):
    d = root / sid
    d.mkdir(parents=True)
    (d / "latency.csv").write_text(LATENCY, encoding="utf-8")
    (d / "micro.csv").write_text(MICRO, encoding="utf-8")
    (d / "adversarial.csv").write_text(adversarial, encoding="utf-8")
    meta = {
        "session_id": sid,
        "eval_tag": "test",
        "commit": "0" * 40,
        "command": "cargo run",
        "profile": "release",
        "date_utc": "2026-08-04T00:00:00Z",
        "host": {
            "os": "Windows 11", "kernel": "26200", "cpu_model": "Intel i7",
            "cpu_cores": "12", "ram_kb": "31457280", "storage": "NVMe",
            "power_mode": "AC-alto-desempenho",
        },
        "toolchain": {"rustc": "rustc 1.96.1"},
    }
    if meta_override:
        meta_override(meta)
    (d / "run-metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    return d


class BooleanParsing(unittest.TestCase):
    """O harness Rust serializa ``true``; ferramentas Python, ``True``."""

    def test_lowercase_blocked_is_not_read_as_unblocked(self):
        # Regressão: comparar contra "True" fazia todo bloqueio legítimo do
        # harness virar "não bloqueado", derrubando 10/10 para 0/10 sem erro.
        self.assertTrue(agg.csv_bool("true", "blocked", "s01"))
        self.assertTrue(agg.csv_bool("True", "blocked", "s01"))
        self.assertTrue(agg.csv_bool("TRUE", "blocked", "s01"))
        self.assertFalse(agg.csv_bool("false", "blocked", "s01"))
        self.assertFalse(agg.csv_bool("False", "blocked", "s01"))

    def test_absent_column_is_false_not_an_error(self):
        self.assertFalse(agg.csv_bool("", "transport_error", "s01"))

    def test_unrecognized_value_aborts_instead_of_defaulting(self):
        with self.assertRaises(SystemExit):
            agg.csv_bool("sim", "blocked", "s01")


class AdversarialRates(unittest.TestCase):
    def _rates(self, adversarial):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sessions = [
                write_session(root, sid, adversarial)
                for sid in ("s01", "s02", "s03")
            ]
            return agg.aggregate_adversarial(sessions)

    def test_legacy_csv_without_transport_column(self):
        legacy = (
            "id,class,blocked,expected_block,pass,description\n"
            "A1,attack,true,true,true,x\n"
            "A2,attack,true,true,true,x\n"
            "C1,control,false,false,true,x\n"
        )
        rows, divergent, terr = self._rates(legacy)
        attack = next(r for r in rows if r[0] == "attack")
        control = next(r for r in rows if r[0] == "control")
        self.assertEqual((attack[3], attack[2]), (6, 6))
        self.assertEqual((control[3], control[2]), (3, 3))
        self.assertEqual(terr, 0)
        self.assertEqual(divergent, [])

    def test_transport_errors_leave_both_rates_untouched(self):
        clean = (
            "id,class,blocked,transport_error,expected_block,pass,description\n"
            "A1,attack,true,false,true,true,x\n"
            "C1,control,false,false,false,true,x\n"
        )
        noisy = clean + (
            "A9,attack,true,true,true,false,ruido\n"
            "C9,control,true,true,false,false,ruido\n"
        )
        base_rows, _, base_terr = self._rates(clean)
        noisy_rows, _, noisy_terr = self._rates(noisy)
        self.assertEqual(base_terr, 0)
        self.assertEqual(noisy_terr, 6)
        # Excluídas do numerador *e* do denominador de ambas as taxas.
        for klass in ("attack", "control"):
            base = next(r for r in base_rows if r[0] == klass)
            noisy_r = next(r for r in noisy_rows if r[0] == klass)
            self.assertEqual(noisy_r[2], base[2], f"denominador de {klass}")
            self.assertEqual(noisy_r[3], base[3], f"numerador de {klass}")


class Statistics(unittest.TestCase):
    def test_wilson_matches_reference_interval(self):
        # Valor de referência publicado para 10/12 a 95%.
        rate, lo, hi = agg.wilson_ci(10, 12)
        self.assertAlmostEqual(rate, 10 / 12, places=6)
        self.assertAlmostEqual(lo, 0.5520, places=3)
        self.assertAlmostEqual(hi, 0.9530, places=3)

    def test_wilson_is_not_the_normal_approximation(self):
        # A aproximação normal colapsa em [0,0] com zero sucessos; Wilson não.
        _, lo, hi = agg.wilson_ci(0, 10)
        self.assertEqual(lo, 0.0)
        self.assertGreater(hi, 0.0)

    def test_wilson_handles_empty_denominator(self):
        self.assertEqual(agg.wilson_ci(0, 0), (0.0, 0.0, 0.0))

    def test_percentile_matches_numpy_default_convention(self):
        """A docstring de boot_ci afirma seguir a convenção linear do numpy.

        Compara a implementação real (extraída do fonte, pois é aninhada em
        ``boot_ci``) contra ``numpy.percentile``. Sem numpy, pula em vez de
        aprovar silenciosamente.
        """
        if importlib.util.find_spec("numpy") is None:
            self.skipTest("numpy ausente")
        import numpy

        src = (HERE / "aggregate.py").read_text(encoding="utf-8")
        start = src.index("def percentile")
        end = src.index("\n\n", src.index("return", start))
        body = "\n".join(
            line[4:] if line.startswith("    ") else line
            for line in src[start:end].split("\n")
        )
        namespace = {}
        exec(body, namespace)  # noqa: S102 - fonte do próprio repositório
        percentile = namespace["percentile"]

        rng = random.Random(7)
        for _ in range(50):
            n = rng.choice([3, 5, 10, 100])
            data = sorted(rng.uniform(0, 100) for _ in range(n))
            for q in (0.025, 0.5, 0.975):
                self.assertAlmostEqual(
                    percentile(data, q),
                    float(numpy.percentile(data, q * 100)),
                    places=9,
                    msg=f"n={n} q={q}",
                )

    def test_bootstrap_on_constant_input_is_degenerate(self):
        rng = random.Random(agg.RNG_SEED)
        mean, lo, hi = agg.boot_ci([5.0] * 5, rng)
        self.assertEqual((mean, lo, hi), (5.0, 5.0, 5.0))

    def test_drift_is_suppressed_below_the_gate_and_active_above(self):
        self.assertIsNone(agg.drift([1.0, 2.0, 3.0]))
        self.assertEqual(agg.drift([1.0, 2.0, 3.0, 4.0]), 1.0)
        self.assertEqual(agg.drift([1.0, 1.0, 1.0, 1.0]), 0.0)


class Integrity(unittest.TestCase):
    def _problems(self, override):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            adversarial = (
                "id,class,blocked,transport_error,expected_block,pass,description\n"
                "A1,attack,true,false,true,true,x\n"
            )
            sessions = [
                write_session(root, sid, adversarial,
                              override if sid == "s02" else None)
                for sid in ("s01", "s02", "s03")
            ]
            return agg.check_integrity(sessions)

    def test_valid_metadata_passes(self):
        self.assertEqual(self._problems(lambda m: None), [])

    def test_null_host_or_toolchain_is_rejected_not_a_crash(self):
        # `meta.get("host", {})` devolve None para {"host": null}: o padrão só
        # cobre a chave ausente. Antes da correção isso derrubava o agregador
        # com AttributeError em vez de rejeitar a sessão.
        for label, override in {
            "host null": lambda m: m.__setitem__("host", None),
            "toolchain null": lambda m: m.__setitem__("toolchain", None),
            "host lista": lambda m: m.__setitem__("host", []),
        }.items():
            with self.subTest(caso=label):
                self.assertTrue(self._problems(override))

    def test_rejects_unusable_and_placeholder_fields(self):
        cases = {
            "espacos": lambda m: m["host"].__setitem__("cpu_model", "   "),
            "sem host": lambda m: m.pop("host"),
            "n/a maiusculo": lambda m: m["host"].__setitem__("power_mode", "N/A"),
            "placeholder": lambda m: m["host"].__setitem__(
                "power_mode", "PLACEHOLDER_FIXAR_ANTES_DA_SESSAO"),
            "rustc ausente": lambda m: m["toolchain"].pop("rustc"),
            "sem toolchain": lambda m: m.pop("toolchain"),
        }
        for label, override in cases.items():
            with self.subTest(caso=label):
                self.assertTrue(self._problems(override),
                                f"{label} deveria ser rejeitado")


if __name__ == "__main__":
    unittest.main(verbosity=2)
