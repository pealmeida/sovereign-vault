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

## Proveniência

Estes CSVs foram produzidos a partir do commit
`dfb0a49f7360aedf37ee89152b99e2d970b6cfd6`, alcançável pela etiqueta anotada
**`thesis-evidence-preliminary`**.

**Esse commit não é ancestral da `main`.** O código instrumentado mudou depois
dele — em particular `a0b51da`, que somou cerca de 925 linhas ao gateway
`sv-mcp` (o componente medido) e 116 ao harness `thesis-eval`. Portanto os
números aqui **não correspondem ao código da versão entregue**.

Isso é consistente com a classificação declarada na tese: execução preliminar de
desenvolvimento, uma sessão, sem intervalo de confiança. A etiqueta existe para
que o commit permaneça alcançável e os resumos publicados sigam verificáveis,
mesmo que a branch de origem seja apagada.

A execução definitiva substituirá tanto estes dados quanto esta âncora, e deverá
ser produzida a partir de um estado publicado da `main`, com etiqueta própria.
