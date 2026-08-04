#!/usr/bin/env python3
"""Regenera os fragmentos da variante USPSC a partir de `paper.tex`.

`paper.tex` é a fonte canônica do conteúdo. A variante `paper-uspsc.tex` só
carrega dois fragmentos extraídos daqui, de modo que o texto nunca é duplicado
e as duas variantes não podem divergir:

* ``uspsc/_pretextual-conteudo.tex`` — resumo, abstract, listas e sumário
  (tudo entre ``\\imprimirfolhaderosto`` e ``\\textual``, menos a ficha e a
  folha de aprovação, que a variante USPSC monta por conta própria);
* ``uspsc/_body.tex`` — corpo textual e pós-textual (de ``\\textual`` até
  ``\\end{document}``).

Executar após qualquer edição em `paper.tex`:

    python scripts/sync-uspsc-body.py
"""
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(__file__).resolve().parent.parent
PAPER = ROOT / "docs" / "thesis" / "paper.tex"
OUT_DIR = ROOT / "docs" / "thesis" / "uspsc"

HEADER = (
    "% GERADO AUTOMATICAMENTE por scripts/sync-uspsc-body.py — NÃO EDITAR.\n"
    "% Fonte canônica: docs/thesis/paper.tex\n"
)


def fail(msg):
    sys.exit(f"erro: {msg}")


def main():
    text = PAPER.read_text(encoding="utf-8")

    start_textual = text.find("\\textual")
    end_doc = text.find("\\end{document}")
    if start_textual < 0 or end_doc < 0:
        fail("não encontrei \\textual ou \\end{document} em paper.tex")

    # --- corpo textual + pós-textual -------------------------------------
    body = text[start_textual:end_doc]

    # --- pré-textual: do fim da folha de aprovação até \textual -----------
    marker = "\\end{folhadeaprovacao}"
    pre_start = text.find(marker)
    if pre_start < 0:
        fail("não encontrei \\end{folhadeaprovacao} em paper.tex")
    pretextual = text[pre_start + len(marker):start_textual]

    # A variante USPSC imprime a capa e a folha de rosto pela própria classe.
    for forbidden in ("\\imprimircapa", "\\imprimirfolhaderosto"):
        if forbidden in pretextual:
            fail(f"fragmento pré-textual contém {forbidden}, que a classe USPSC já emite")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "_body.tex").write_text(HEADER + body, encoding="utf-8")
    (OUT_DIR / "_pretextual-conteudo.tex").write_text(
        HEADER + pretextual, encoding="utf-8"
    )

    # --- conferência de integridade --------------------------------------
    combined = pretextual + body
    cites = {k.strip() for group in re.findall(r"\\cite\{([^}]+)\}", combined)
             for k in group.split(",")}
    items = set(re.findall(r"\\bibitem\{([^}]+)\}", combined))
    orphans = sorted(cites - items)
    if orphans:
        fail(f"citações sem \\bibitem nos fragmentos: {orphans}")

    print(f"_body.tex: {body.count(chr(10))} linhas")
    print(f"_pretextual-conteudo.tex: {pretextual.count(chr(10))} linhas")
    print(f"citações: {len(cites)} · entradas: {len(items)} · órfãs: 0")


if __name__ == "__main__":
    main()
