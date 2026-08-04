# Evidência versionada do Capítulo 4

Cópias fiéis dos artefatos produzidos por `thesis-eval` e citados no Capítulo 4 e
no apêndice de reprodutibilidade.

**Por que existem.** A saída do harness vai para `target/thesis-eval/`, que é
ignorado pelo Git (`**/target/`). A tese publica os resumos SHA-256 desses
arquivos, mas um avaliador que clonasse o repositório não conseguiria recuperá-los
nem conferir os resumos. Sem isso, a rastreabilidade da evidência não se sustenta.

| Arquivo | SHA-256 |
|---|---|
| `latency.csv` | `2e914c1bbd7b290c9aa4c5e143227f08b6f581884d436ccbbd965df7d2649adc` |
| `adversarial.csv` | `845a1d042ba68d52123d726c415dc2b21e50f39e3f708ccfc3a18788d2e81d5f` |
| `micro.csv` | `d526ed70ebf659e72247a53ddd4de27dbf2a3ffc789c421b1d4e95fc056bf4c6` |

Conferir com:

```bash
sha256sum docs/thesis/evidence/*.csv
```

## Regenerar

```bash
cargo run --release -p thesis-eval -- all --out target/thesis-eval --iterations 1000
cp target/thesis-eval/{latency,adversarial,micro}.csv docs/thesis/evidence/
```

Ao regenerar, **atualize também os resumos no apêndice de `paper.tex`**. Números
no texto que não correspondam aos arquivos versionados são defeito grave de
reprodutibilidade.

## Estado dos dados

Execução **preliminar** de desenvolvimento: uma sessão, sem intervalo de
confiança. A execução definitiva exige k ≥ 3 sessões independentes, IC de 95% por
*bootstrap* e regra explícita de *warmup*/descarte, conforme já declarado no
próprio texto da tese.

> **Pendência de proveniência.** O apêndice declara o commit
> `dfb0a49f7360aedf37ee89152b99e2d970b6cfd6`. Ele existe, mas **não é ancestral
> da `main`** — está apenas na branch `feat/headless-serve-migrate-ratelimit`. Se
> essa branch for apagada, a âncora de proveniência desaparece. Antes da entrega,
> criar uma tag anotada apontando para o commit da execução definitiva, e citar
> essa tag no apêndice.
