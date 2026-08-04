# Passos finais de entrega — o que só o autor pode fazer

**Estado em 04/08/2026.** Tudo que podia ser implementado, verificado ou
automatizado foi feito e está commitado. Este documento lista o que resta, com
o comando ou a ação exata para cada item. Nenhum passo abaixo exige decisão
técnica: exigem informação que não existe neste repositório, ou uma condição de
ambiente que não pode ser verificada por automação.

---

## 1. Nome do orientador (2 minutos)

**Onde:** `docs/thesis/paper.tex`, linha do `\orientador{}`.

```latex
\orientador{[ORIENTADOR(A) A CONFIRMAR]}
```

Substituir pelo nome com titulação, no formato usado pelo ICMC (ex.:
`Prof. Dr. Fulano de Tal`). O *placeholder* é intencionalmente visível no PDF.

> **Por que não foi preenchido automaticamente:** o nome não consta de nenhum
> arquivo deste repositório, e o comentário no próprio `paper.tex` adverte
> contra assumir que seja a coordenadora do curso. Um nome inventado numa folha
> de rosto é um registro acadêmico falso — pior que um marcador visível.

A folha de aprovação herda o mesmo campo via `\imprimirorientador`; preencher
num lugar resolve os dois.

---

## 2. Ficha catalográfica (10 minutos)

**Gerar em:**
<https://www.icmc.usp.br/institucional/estrutura-administrativa/biblioteca/servicos/ficha>

**Colar em:** `docs/thesis/paper.tex`, dentro de `\begin{fichacatalografica}`,
substituindo o bloco `[FICHA CATALOGRÁFICA A GERAR]` — **sem reformatar** o
texto devolvido pelo sistema.

A estrutura já está correta: a ficha cai no verso da folha de rosto (página 4 do
PDF), como exige a NBR 14724. Nada além do texto precisa mudar.

---

## 3. Decisão: migrar para o pacote USPSC 3.2? (conversa com a orientadora)

As fontes das disciplinas declaram o pacote **obrigatório** (siglas `MBAIAp` /
`MBAIAe`). O documento usa `abntex2` puro, que compila limpo hoje.

| Opção | Consequência |
|---|---|
| Migrar | Cumpre a exigência declarada; traz pré-textuais e citação ABNT prontos; reorganiza a estrutura de arquivos a ~4 meses do prazo |
| Manter | Zero retrabalho; descumpre exigência explícita; risco na banca |

O pacote **não** está no CTAN nem instalado nesta máquina — vem do repositório
da USP. A migração mexe no documento inteiro e não deve ser feita sem
confirmação. **Confirmar com a orientadora antes de decidir.**

---

## 4. Execução definitiva da avaliação (≈2 h de máquina)

Instrumento pronto, testado e **ensaiado de ponta a ponta**. O que falta é rodar
sob as pré-condições que o próprio protocolo exige.

### Pré-condições (§1 de `EXECUCAO-DEFINITIVA.md`)

1. **Integrar este ramo à `main`** e publicar. O protocolo exige etiqueta
   anotada sobre um commit alcançável da `main`; medir fora disso reproduz o
   defeito de proveniência que o apêndice já documenta (evidência não-ancestral).
2. **Host controlado:** plano de energia fixo em Alto Desempenho, na tomada,
   navegador/IDE/Docker/sync de nuvem fechados, sem *build* concorrente.

> **Por que isso não foi disparado automaticamente:** o ensaio de validação, com
> sessões curtas nesta máquina em uso, produziu CV de até 65% em algumas células
> — ruído de ambiente muito acima do sinal de dezenas de microssegundos que se
> quer medir. É exatamente o que a §1.5 existe para evitar. Rodar assim geraria
> números que o próprio protocolo classifica como inválidos.

### Sequência

```bash
git checkout main && git pull --ff-only
git status --porcelain          # deve imprimir nada

EVAL_TAG=thesis-eval-v1
git tag -a "$EVAL_TAG" -m "Definitive evaluation harness run anchor"

# Repetir para s01..s05, com uma seed distinta por sessão:
SESSION=s01; SEED=1701
CMD="cargo run --release -p thesis-eval -- all --out target/thesis-eval/sessions/$SESSION --iterations 2000 --warmup 200 --seed $SEED"
bash docs/thesis/evidence/collect-metadata.sh \
    target/thesis-eval "$SESSION" "$EVAL_TAG" "AC-alto-desempenho" "$CMD"
eval "$CMD"

# Após as cinco sessões:
python3 docs/thesis/evidence/aggregate.py target/thesis-eval/sessions docs/thesis/evidence
```

O agregador sai com código **2** se houver ressalvas (§6) e **1** se a
integridade falhar (§6.5). Só publicar a etiqueta (`git push origin $EVAL_TAG`)
depois de conferir que os números do Capítulo 4 batem com os CSVs.

### Depois da execução

Substituir no `paper.tex`: os números do Cap. 4, os resumos SHA-256 do apêndice,
o commit/etiqueta de proveniência, e trocar as qualificações de "execução
preliminar de uma sessão sem IC" pelos valores com k=5 e IC de 95%. As
qualificações que **permanecem** (bateria finita, HITL simulada, cargas
sintéticas, ausência de precisão/recall) estão marcadas no texto e não devem ser
removidas.

---

## 5. A confirmar com a coordenação

- Folha de aprovação: exigida já na submissão ou só no depósito final? (a
  estrutura está pronta em branco, que é a variante submetível)
- Relatório antiplágio (Turnitin ou similar): exigido?
- Declaração de uso de IA: exigida? O material para redigi-la existe e é
  rastreável (ADRs, `docs/thesis/review/`).
- `oneside` vs `twoside` — provavelmente resolvido pelo USPSC (item 3).
- Lista de símbolos: exigida pelo programa?

---

## O que já está garantido

| Item | Estado verificado |
|---|---|
| Compilação | 50 páginas, 0 erros, 0 citações/referências indefinidas, 0 *overfull* |
| Estrutura ABNT pré-textual | capa, folha de rosto, ficha (verso), folha de aprovação, resumo/abstract, listas, sumário |
| Citações código↔tese | 13/13 faixas válidas (`scripts/check-thesis-citations.py`) |
| Testes do harness | 5/5 (`cargo test -p thesis-eval`), clippy limpo |
| Testes do agregador | 14/14 (`docs/thesis/evidence/test_aggregate.py`) |
| Cadeia de medição | ensaiada de ponta a ponta em dados reais do harness |
| CI | compila o PDF e falha em citação/referência indefinida; roda os dois conjuntos de teste |
| Pareceres | R9–R14; todos os achados acionáveis implementados ou respondidos com justificativa |
