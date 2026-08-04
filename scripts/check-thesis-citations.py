import re, os, sys

TEX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "thesis", "paper.tex")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

tex = open(TEX, encoding="utf-8").read()

# conteudo de todos os \codigo{...}
cits = re.findall(r"\\codigo\{([^}]*)\}", tex)

# citacoes com arquivo:linha (linha unica, faixa, ou lista separada por virgula)
pat = re.compile(r"^([\w./\-]+\.(?:rs|json|toml)):([\d,\-]+)$")

alvo = []
for c in cits:
    m = pat.match(c.strip())
    if m:
        alvo.append((c.strip(), m.group(1), m.group(2)))

print("total de \\codigo{} :", len(cits))
print("com arquivo:linha  :", len(alvo))
print()

def faixas(spec):
    out = []
    for parte in spec.split(","):
        parte = parte.strip()
        if "-" in parte:
            a, b = parte.split("-", 1)
            out.append((int(a), int(b)))
        elif parte:
            out.append((int(parte), int(parte)))
    return out

problemas = []
for cit, arq, spec in sorted(set(alvo)):
    full = os.path.join(ROOT, arq.replace("/", os.sep))
    if not os.path.exists(full):
        problemas.append((cit, "ARQUIVO INEXISTENTE", ""))
        print("[X] %-62s  ARQUIVO INEXISTENTE" % cit)
        continue
    n = sum(1 for _ in open(full, encoding="utf-8", errors="replace"))
    ruins = [f for f in faixas(spec) if f[1] > n]
    if ruins:
        problemas.append((cit, "FORA DO FIM (arquivo tem %d linhas)" % n, ""))
        print("[X] %-62s  FORA DO FIM (arquivo tem %d linhas)" % (cit, n))
    else:
        print("[ok] %-61s  (arquivo tem %d linhas)" % (cit, n))

print()
print("citacoes com faixa invalida:", len(problemas))
