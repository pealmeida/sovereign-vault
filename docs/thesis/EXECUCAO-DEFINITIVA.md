# Protocolo operacional — execução definitiva da avaliação

Este documento é um **procedimento**, não um ensaio: passos numerados, comandos
concretos, justificativas em uma linha. Ele substitui a execução preliminar de
desenvolvimento descrita em `docs/thesis/evidence/README.md` pela execução
definitiva que cumpre a régua declarada em `AGENTS.md` §4 e em
`EVAL-PROTOCOL.md`.

A unidade que executa estes passos é o **autor** (pessoa), em uma máquina. O
agente não mede nem publica números — apenas escreve o protocolo e os scripts.

---

## Resumo — o que muda em relação à execução preliminar

| Dimensão | Preliminar (atual) | Definitiva (este protocolo) |
|---|---|---|
| Origem do código | commit `dfb0a49`, **não ancestral da `main`** | tag anotada criada sobre a `main` publicada |
| Sessões | 1 | k = 5 (com regra explícita de descarte de sessão outlier) |
| Itererações por célula | 1.000 | 2.000 (após descartar 200 de *warmup*) |
| Incerteza | nenhuma reportada | IC de 95% por *bootstrap* pareado, 10.000 reamostragens |
| Agregação | média simples por sessão | média das médias de sessão, com IC sobre as sessões |
| Ordem das condições | fixa (ordem do código) | randomizada por sessão via *seed* declarada |
| *Warmup* | 1 leitura isolada não cronometrada | 200 iterações por célula descartadas, registradas |
| Metadados | nenhum | `run-metadata.json` automático por sessão + agregado |
| Estado do *host* | não controlado | energia fixa, sem compilação concorrente, sem UI pesada |
| Armazenamento dos dados | `docs/thesis/evidence/*.csv` sobrescritos | `docs/thesis/evidence/sessions/sNN/*.csv` + CSVs agregados |

A execução preliminar **permanece** alcançável pela etiqueta
`thesis-evidence-preliminary` e seus resumos continuam verificáveis. A execução
definitiva os substitui no texto e no apêndice, e recebe etiqueta própria.

---

## Bloqueante: o harness ainda não suporta este protocolo

Verificado em `apps/thesis-eval/src/main.rs`: o binário aceita **apenas** `--out`
e `--iterations` (linhas 61–62). Não existe `--warmup`, não existe `--seed`, e
não há descarte de iterações em lugar nenhum do código.

Isso é uma lacuna real entre o que a tese promete e o que o artefato faz: o
próprio texto declara que a execução definitiva exige "regra explícita de
\textit{warmup}/descarte". Hoje o harness não sabe executá-la.

| # | Falta | Onde | Necessário para |
|---|---|---|---|
| 1 | `--warmup N` com descarte das N primeiras iterações por célula | `run_latency`, `run_micro` | §2.4 |
| 2 | `--seed` e randomização da ordem das condições | `run_latency` | §2.2 |
| 3 | Emissão de `run-metadata.json` | ambos | §3.6 |

**Ordem correta de trabalho:** implementar (1) e (2) — (3) tem alternativa via
script externo — e só então executar o protocolo. Executá-lo antes produziria
dados que não cumprem a régua declarada, o que é pior do que não executar.

Enquanto (1) e (2) não existirem, a alternativa de pós-processamento descrita no
§2.6 é o caminho degradado: ela é possível, mas exige declarar no texto que o
descarte foi feito fora do instrumento, e não pelo instrumento.

---

## 1. Pré-condições

> **Justificativa de todas as restrições:** o microbenchmark mede latências da
> ordem de dezenas de microssegundos; qualquer variação de estado do *host*
> (frequência de CPU, *governor*, agendador, cache quente de build) é maior que
> o sinal que se quer medir. As pré-condições existem para tornar a variância
> entre sessões atribuível ao artefato, não ao ambiente.

1. **Repositório limpo e sincronizado.** Na raiz:

   ```bash
   git status --porcelain          # deve imprimir nada
   git checkout main
   git pull --ff-only
   ```

   Se `git status` listar qualquer coisa, resolva ou faça *stash* antes de
   prosseguir. Medir sobre uma árvore suja invalida a rastreabilidade do commit.

2. **Criar a etiqueta anotada da execução.** Escolha um nome estável
   (`thesis-eval-v1`) e registre commit + data:

   ```bash
   EVAL_TAG=thesis-eval-v1
   git tag -a "$EVAL_TAG" -m "Definitive evaluation harness run anchor"
   git rev-parse --short HEAD          # anote para run-metadata.json
   git rev-parse "$EVAL_TAG^{commit}"  # hash completo
   ```

   > **Não faça `git push` da etiqueta** até confirmar, ao final do §6, que os
   > números da tese batem com os CSVs. A etiqueta só é publicada quando o
   > apêndice de reprodutibilidade está consistente. (Regra de `AGENTS.md` §6:
   > o autor revisa antes de publicar.)

3. **Perfil `release` confirmado.** O comando do §3.6 usa `--release`
   explicitamente. Verifique que não há `CARGO_PROFILE_RELEASE_DEBUG=true`
   exportado nem *overrides* de perfil no *shell*:

   ```bash
   env | grep -i cargo || echo "(nenhum override de cargo)"
   ```

   > *Justificativa:* `debug=true` no perfil *release* inflaciona latência por
   > falta de otimizações e torna os números não reportáveis conforme
   > `AGENTS.md` §4.

4. **Compilação antecipada, fora da janela de medição.** Antes de qualquer
   sessão, faça a compilação completa e deixe o binário pronto:

   ```bash
   cargo build --release -p thesis-eval
   ```

   > *Justificativa:* compilar durante a medição disputa CPU/disco e aquece o
   > *package* de relevos. Compilar antes e apenas executar o binário remove
   > essa fonte de variância.

5. **Estado do *host* estabilizado.** Executar em uma máquina de trabalho
   típica, sem exigir hardware especial. Antes de **cada** sessão:

   - Fechar navegador, IDEs, *containers* Docker, *sync* de nuvem e qualquer
     processo que consuma CPU ou disco de forma variável.
   - Travar o plano de energia (Windows: Alto Desempenho; Linux: *performance
     governor*). Registrar o modo no `run-metadata.json` (§3).
   - Garantir que não haja compilação, *indexing* de IDE ou *backup* rodando.
   - Conectar à tomada (notebook em bateria muda o *governor* e o *turbo*).

   > *Justificativa:* a régua de `AGENTS.md` §4 exige registro de "modo de
   > energia"; o modo precisa estar **fixo** durante toda a sessão, não apenas
   > reportado.

6. **Checar a versão do `rustc` que será usada.** Anote-a; ela entra no
   `run-metadata.json`:

   ```bash
   rustc --version --verbose
   ```

   > *Justificativa:* o apêndice de reprodutibilidade da tese declara a
   > *toolchain*; um leitor que reproduzir precisa do mesmo `rustc`.

---

## 2. Desenho experimental

### 2.1 Parâmetros numéricos

| Parâmetro | Valor | Justificativa (uma linha) |
|---|---|---|
| k (sessões independentes) | **5** | ≥3 é o mínimo declarado; 5 permite descartar 1 outlier e ainda manter n=4, suficiente para IC por *bootstrap*. |
| Iterações cronometradas por célula | **2.000** | Dobro do preliminar (1.000) reduz o erro-padrão da média por sessão em ~30% e melhora a estabilidade do p95. |
| *Warmup* (descartadas por célula) | **200** | ~10% das iterações; aquece cache de instrução/dados e estabiliza *turbo boost*. O harness hoje faz **1** leitura isolada não cronometrada, insuficiente — ver §2.5. |
| Células | 4 modos × 3 tamanhos = 12 | Definidos pelo harness (`direct, approval, otp, anon` × `128, 1024, 16384` B); não mudar sem reescrever o desenho. |
| Reamostragens de *bootstrap* | **10.000** | Erro de Monte Carlo do IC < 1% da largura para IC de 95%; barato. |
| Semente de aleatorização | declarada por sessão | Permite auditoria da ordem; *seed* fixa → sequência reproduzível. |

### 2.2 Ordem de execução das condições

- A ordem das 12 células **dentro de cada sessão** deve ser **randomizada** por
  sessão, usando uma *seed* declarada no `run-metadata.json`.
- O harness atual executa as células em **ordem fixa** (modo × tamanho, na
  ordem do código em `run_latency`). **Isso requer alteração em
  `apps/thesis-eval`** — ver §2.6.

  > *Justificativa:* ordem fixa confunde efeito de aquecimento/deriva com efeito
  de condição; randomização distribui os efeitos residuais de tempo entre as
  células. Como o *warmup* é por célula, a randomização também protege contra
  deriva térmica entre o início e o fim da sessão.

- A ordem dos **subcomandos** (`latency` → `micro` → `adversarial`) pode
  permanecer fixa: `latency` e `micro` são os sensíveis à ordem; `adversarial`
  é determinístico (contagem de bloqueios, não latência) e sua ordem interna de
  sondas não afeta o resultado.

### 2.3 O que constitui "sessão independente"

- **Sessão = um processo novo** do harness (`cargo run` ou execução direta do
  binário), precedido de pelo menos **5 minutos** de intervalo desde a sessão
  anterior e com a árvore de *working tree* inalterada.
- **Não é exigido reinício de máquina** entre sessões: a estabilização do
  *host* (§1.5) mais o intervalo de 5 min mais o *warmup* por célula cobrem a
  deriva térmica residual. Se, no §5, for detectada deriva térmica entre
  sessões, **aí sim** exigir reinício completo entre cada par de sessões e
  refazer.
- Cada sessão escreve em um diretório próprio: `target/thesis-eval/sessions/sNN/`.

  > *Justificativa:* reiniciar processo recria o *vault* *throwaway* (que o
  harness já faz), reinicializa caches do processo e quebra qualquer
  dependência de estado entre execuções. O intervalo de 5 min dá tempo de o
  *governor* e a temperatura voltarem ao patamar. Reinício de máquina é
  dispendioso e só se justifica se a deriva entre sessões exceder o critério
  do §5.

### 2.4 *Warmup* e descarte

- Para cada célula, as **primeiras 200 iterações** são executadas mas **não**
  entram no resumo estatístico gravado no CSV.
- O harness atual **não separa** *warmup* do corpus medido: ele faz uma única
  leitura não cronometrada (`let _ = handle.read_file(...)`) na célula de
  *micro*, mas na célula de *latency* **não há descarte** — todas as
  `iterations` leituras vão para o `TimingSink`. **Isso requer alteração em
  `apps/thesis-eval`** — ver §2.6.

  > *Justificativa:* sem descarte explícito, as primeiras iterações (cache frio,
  *page faults*, *turbo* subindo) ficam misturadas e inflacionam média e p95.
  Descartar 200 das 2.200 executadas deixa 2.000 medidas limpas.

### 2.5 *Adversarial*: sem *warmup*, sem repetição interna

- O braço `adversarial` é uma bateria **finita e determinística** (12 sondas).
  Não há *warmup*: não é um microbenchmark. A taxa de bloqueio é uma contagem,
  não uma estatística de centralidade.
- **Repetir a bateria nas k sessões** serve para detectar não-determinismo
  (ex.: uma sonda que às vezes falha por *timeout* de transporte). Reporta-se
  a taxa de bloqueio como **fração observada sobre k × 12 execuções**, com IC
  exato de Wilson (não *bootstrap*, que é inadequado para proporção binária).

  > *Justificativa:* a bateria é pequena (n=12 por sessão); o IC de Wilson é o
  recomendado para proporções com n pequeno e não recorre à normalidade.

### 2.6 Alterações necessárias no harness

As mudanças a seguir **requerem alteração em `apps/thesis-eval`** e devem ser
feitas e testadas **antes** de iniciar a sessão s01. Sem elas, o protocolo não
é cumprível com o binário atual:

1. **Aceitar `--warmup N`** em `run_latency` e `run_micro`: executar `N`
   iterações adicionais por célula, registrando-as no `TimingSink` mas
   descartando-as do `Vec` que alimenta `summarize`. Concretamente: chamar
   `drive_reads_stdio` uma primeira vez com `warmup` iterações e descartar os
   `StageTimings` resultantes, depois chamar com `iterations` e guardar.

2. **Aceitar `--seed S`** e usar `S` (via `rand` ou um *shuffle*
   determinístico) para permutar a ordem do loop `for (name, _mode) in modes`
   em `run_latency`. Registrar `S` na saída.

3. **Escrever `run-metadata.json`** (§3) — idealmente o próprio binário coleta
   `rustc`, data, etc.; o script em §3 é o caminho mínimo caso o binário não o
   faça.

> **Recomendação operacional:** implementar (1) e (2) no harness é mais
> robusto do que embarcar a lógica em *shell*. O script de §3 pode suprir (3)
> sem mudança de código. Se o autor preferir não alterar o harness, **o
> protocolo não pode ser cumprido como escrito** — registrar a limitação na
> seção de riscos (§7) e recuar para ordem fixa + *warmup* externo (descartar
   as primeiras 200 linhas por célula em pós-processamento), declarando isso
> explicitamente no texto.

---

## 3. Registro de ambiente (`run-metadata.json`)

### 3.1 Script de captura

Criar `docs/thesis/evidence/collect-metadata.sh` (não versionar dados, apenas o
script). Ele captura tudo o que a régua exige e grava no diretório da sessão:

```bash
#!/usr/bin/env bash
# Uso: collect-metadata.sh <sessions_dir> <session_id> <eval_tag> <command_line...>
set -euo pipefail
OUT_DIR="$1"; SESSION_ID="$2"; EVAL_TAG="$3"; shift 3
COMMAND="$*"

SESSION_DIR="$OUT_DIR/sessions/$SESSION_ID"
mkdir -p "$SESSION_DIR"

META="$SESSION_DIR/run-metadata.json"

# Plataforma-agnóstico o possível; captura vazio se a fonte não existir.
KERNEL=$(uname -r 2>/dev/null || echo "n/a")
OS=$(uname -s 2>/dev/null || echo "n/a")
CPU_MODEL=$(cat /proc/cpuinfo 2>/dev/null | grep -m1 'model name' | cut -d: -f2 | sed 's/^ *//' || echo "n/a")
CPU_CORES=$(nproc 2>/dev/null || echo "n/a")
RAM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "n/a")
STORAGE=$(df -h "$OUT_DIR" 2>/dev/null | tail -1 | awk '{print $1" "$2" "$4" free"}' || echo "n/a")
RUSTC=$(rustc --version 2>/dev/null || echo "n/a")
# No Windows, uname/proc não existem; preencher manualmente os campos marcados n/a
# antes de executar o harness, lendo de systeminfo / wmic.

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
    "power_mode": "PLACEHOLDER_FIXAR_ANTES_DA_SESSAO"
  },
  "toolchain": {
    "rustc": "$RUSTC"
  }
}
EOF

echo "metadata -> $META"
```

> **Nota Windows:** o autor está em `C:\Users\pealm\AppData\Local\...`
> (AGENTS.md §5). Os campos `model name`, `MemTotal`, `df` virão `n/a`. Antes
> de cada sessão, preencher `cpu_model`, `ram_kb`, `storage`, `power_mode`
> manualmente a partir de `systeminfo` / `wmic cpu get name` / Configurações de
> Energia. O script deixa os *placeholders* explícitos para que nada fique em
> branco silencioso.

> **Justificativa do conteúdo:** cada campo corresponde a uma dimensão que muda
> a latência medida (cache size do CPU, RAM livre, tipo de disco, perfil de
> energia, versão do compilador). Sem eles, um leitor não consegue julgar se os
> números são plausíveis na própria máquina.

### 3.2 Aplicação por sessão

Para cada sessão `sNN` (s01…s05), antes de executar o harness, rodar o script.
Exemplo para a sessão 01:

```bash
cd /d/Code/sovereign-vault   # ou o caminho Windows equivalente
EVAL_TAG=thesis-eval-v1
SESSION=s01
CMD="cargo run --release -p thesis-eval -- all --out target/thesis-eval/sessions/$SESSION --iterations 2000 --warmup 200 --seed 1701"

bash docs/thesis/evidence/collect-metadata.sh \
    target/thesis-eval "$SESSION" "$EVAL_TAG" "$CMD"
```

> O `--warmup` e `--seed` **pressupõem a alteração do harness de §2.6**. Sem
> ela, remover essas bandeiras e aplicar o descarte em pós-processamento (§4).

---

## 4. Execução das sessões

Repetir o bloco abaixo **cinco vezes**, alterando `SESSION` (s01…s05), `--seed`
(uma *seed* diferente por sessão, ex.: 1701, 2847, 3913, 4602, 5290) e o
intervalo:

1. Confirmar pré-condições (§1.5): fechar apps, fixar energia, na tomada.
2. Coletar metadados (§3.2).
3. Esperar **5 minutos** desde o fim da sessão anterior (exceto a primeira).
4. Executar:

   ```bash
   cargo run --release -p thesis-eval -- all \
       --out target/thesis-eval/sessions/sNN \
       --iterations 2000 --warmup 200 --seed SEED_NN
   ```

5. Confirmar que `target/thesis-eval/sessions/sNN/{latency,adversarial,micro}.csv`
   e `run-metadata.json` foram escritos.
6. Antes da próxima sessão, **não** compilar nada nem editar código.

> *Justificativa do intervalo de 5 min:* permite que a temperatura do CPU volte
> ao patamar de repouso e que o *governor* desça a frequência; é a janela mínima
> para que a próxima sessão comece em estado comparável.

---

## 5. Análise e agregação

### 5.1 Script de agregação

Criar `docs/thesis/evidence/aggregate.py` (não versionar saída). Requisitos:
Python 3 com `numpy` e `scipy` (ou `statistics` puro se `numpy` indisponível —
ver nota no fim do §5). O script:

1. Carrega `latency.csv` de cada `sessions/sNN/`.
2. Para cada (modo, bytes, estágio), reúne as **médias das k sessões** em um
   vetor `m_1 … m_k`.
3. Reporta:
   - **estatística pontual:** média de `m_1 … m_k` ("média das médias");
   - **IC de 95%:** *bootstrap* não paramétrico sobre o vetor de médias, com
     10.000 reamostragens, método percentílico.

> *Justificativa da "média das médias" + IC sobre sessões:* a unidade
> independente é a **sessão**. Tirar IC sobre as iterações *dentro* de uma
> sessão subestima a variância entre sessões (pseudorreplicação). O desenho
> correto: média dentro da sessão (estatística suficiente dado o n grande),
> depois IC sobre as k médias de sessão.

### 5.2 Esqueleto do agregador

```python
import csv, glob, json
import numpy as np

B = 10_000  # reamostragens de bootstrap
rng = np.random.default_rng(20260606)

# cell -> {stage -> [mean_s1, mean_s2, ...]}
cells = {}
for path in sorted(glob.glob("target/thesis-eval/sessions/s*/latency.csv")):
    with open(path) as f:
        for row in csv.DictReader(f):
            key = (row["mode"], int(row["bytes"]), row["stage"])
            cells.setdefault(key, []).append(float(row["mean_us"]))

def boot_ci(vals, B=B):
    vals = np.array(vals)
    means = [rng.choice(vals, size=len(vals), replace=True).mean() for _ in range(B)]
    return float(vals.mean()), float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))

rows = []
for (mode, size, stage), vals in sorted(cells.items()):
    if len(vals) < 3:
        raise SystemExit(f"célula ({mode},{size},{stage}) tem só {len(vals)} sessões; mínimo 3")
    mean, lo, hi = boot_ci(vals)
    rows.append((mode, size, stage, len(vals), mean, lo, hi))

with open("docs/thesis/evidence/latency-aggregated.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["mode","bytes","stage","k_sessions","mean_us","ci95_lo","ci95_hi"])
    w.writerows(rows)

print("latency-aggregated.csv escrito;", len(rows), "linhas")
```

> **Se `numpy` não estiver disponível** na máquina do autor, reescrever com
> `random.choices` da biblioteca padrão (mais lento, mas mesmo resultado). O
> método percentílico é trivial de reimplementar ordenando as 10.000 médias.
> **Não recorrer à aproximação normal** (t-Student) sem justificar — o
> protocolo de `EVAL-PROTOCOL.md` pede *bootstrap* explicitamente.

### 5.3 Adversarial: agregação diferente

- Sobre as k execuções de `adversarial.csv`, somar bloqueios por sonda e por
  classe. Taxa de bloqueio = (bloqueios totais) / (k × n_ataques).
- IC de **Wilson** de 95% sobre a proporção. Implementação direta em `scipy`
  ou pela fórmula fechada; não usar *bootstrap*.

> *Justificativa:* *bootstrap* sobre proporções com n pequeno (12 sondas × 5
> sessões = 60 observações por classe, e 5 por sonda individual) tem cobertura
> pobre; Wilson é o padrão para esse caso.

### 5.4 Tratamento de *outliers*

- **Não descartar iterações individuais** dentro de uma sessão por serem
  "altas": o p95 existe justamente para resumir a cauda. Descartar por valor é
  censura.
- **Descartar uma sessão inteira** só se violar o critério de aceitação do §6
  (variabilidade entre sessões). Se descartar, registrar o motivo no
  `run-metadata.json` agregado e reportar k=4.
- Não é permitido **aumentar** k depois de ver os resultados para "forçar" um
> IC estreito. Se a régua exigir mais sessões, declarar antes de medir.

---

## 6. Critério de aceitação da própria execução

Antes de declarar os números válidos, verificar:

1. **Variabilidade entre sessões.** Para cada (modo, bytes, estágio),
   calcular `CV = desvio-padrão das k médias / média das k médias`. Critério:
   - **Aceitável:** CV ≤ 10%.
   - **Limítrofe:** 10% < CV ≤ 20% — reportar, mas sinalizar incerteza na
     legenda da tabela.
   - **Inaceitável:** CV > 20% — investigar antes de aceitar.

   > *Justificativa dos limites:* com latências de dezenas de µs, CV de 10% é
   > compatível com microbenchmarks bem controlados; acima de 20% a variância
   > entre sessões domina o efeito das condições e a comparação perde sentido.

2. **Ausência de deriva térmica.** Para cada célula, plotar a média por
   sessão na ordem s01→s05. Se houver **tendência monotônica** (crescente ou
   decrescente) com `|ρ de Spearman| > 0.8`, há deriva. Ação: exigir reinício
   de máquina entre sessões (§2.3) e refazer.

3. **Concordância do adversarial.** Cada sonda deve dar o **mesmo veredito**
   (bloqueada/não) em todas as k sessões. Qualquer divergência indica
   não-determinismo (ex.: *timeout* de transporte) e deve ser investigada,
   não mascarada pela média.

4. **Sessão divergente.** Se uma sessão tem média sistematicamente > 3
   desvios-padrão das demais em mais da metade das células, ela é candidata a
   *outlier*. Antes de descartar: inspecionar o `run-metadata.json` dela
   (energia mudou? outro processo?). Se o motivo for identificável e
   corrigível, refazer a sessão (mesma *seed*) e substituir. Se não for
   identificável, descartar e reportar k=4 com nota.

5. **Integridade dos arquivos.** Confirmar que cada `sessions/sNN/` contém os
   três CSVs + `run-metadata.json`, e que nenhum CSV está truncado
   (contagem de linhas por célula = `iterations` para `latency`/`micro`,
   12 linhas + cabeçalho para `adversarial`).

---

## 7. Atualização da tese (checklist pós-execução)

Executar **somente depois** de o §6 ter passado. O autor é quem edita
`paper.tex`; este é o checklist do que precisa mudar, não uma autorização para
um agente editar o texto.

1. **Tabelas do Capítulo 4.** Substituir os valores pontuais pelos novos:
   - coluna de média → média das k sessões;
   - adicionar colunas `IC 95% [lo, hi]` ao lado de cada média de latência;
   - para `adversarial`, reportar taxa de bloqueio como proporção com IC de
     Wilson.
2. **Figura de decomposição de latência.** Regenerar a partir de
   `latency-aggregated.csv` (a fonte do `pgfplots` deve apontar para o CSV
   agregado, não para uma sessão individual). Confirmar que `ytick=data` usa
   coordenadas numéricas (regra de `AGENTS.md` §5).
3. **Hashes SHA-256 do apêndice.** Recalcular para os arquivos **finais**
   versionados em `docs/thesis/evidence/`:

   ```bash
   sha256sum docs/thesis/evidence/latency-aggregated.csv \
             docs/thesis/evidence/adversarial-aggregated.csv \
             docs/thesis/evidence/micro-aggregated.csv
   ```

   Colar os resumos no apêndice de reprodutibilidade, **no lugar** dos três
   resumos atuais (`2e914c1b…`, `845a1d04…`, `d526ed70…`).

4. **Commit e etiqueta declarados.** Atualizar o texto que cita a proveniência:
   - commit: o `HEAD` sobre o qual a etiqueta foi criada;
   - etiqueta: `thesis-eval-v1` (anotada);
   - *toolchain*: `rustc` do `run-metadata.json`.
5. **Texto em prosa.** Toda menção a "execução preliminar", "uma sessão",
   "sem intervalo de confiança" deve ser substituída pela descrição definitiva
   (k=5, IC 95% por *bootstrap*, descarte de *warmup*). Não deixar resquícios
   de qualificação preliminar — seria contraditório com a régua cumprida.
   - Manter, porém, as qualificações que **não** dependem do número de sessões
     (ex.: "T_hitl reflete apenas a sobrecarga de despacho, não decisão
     humana" — isso permanece verdadeiro).
6. **`docs/thesis/evidence/README.md`.** Atualizar a tabela de resumos e a
   seção "Proveniência": remover o aviso de que o commit não é ancestral da
   `main`; declarar a nova etiqueta como ancestral da `main`.
7. **Compilar a tese** com 2–3 passadas de `pdflatex` e **apagar artefatos de
   build** (`paper.aux`, `.log`, `.out`, `.toc`, `.lof`, `.lot`, `.pdf`) —
   regra de `AGENTS.md` §5. Não reportar sucesso sem compilar.
8. **Publicar a etiqueta** (`git push origin thesis-eval-v1`) só depois de o
   §7.3 e §7.5 estarem consistentes.

---

## 8. Riscos — o que invalida a execução e como detectar

| Risco | Como detectar | Ação |
|---|---|---|
| *Host* aquece e muda de *turbo* durante a sessão | Deriva monotônica no §6.2 | Reiniciar entre sessões, refazer. |
| Energia em modo econômico em alguma sessão | Campo `power_mode` divergente entre `run-metadata.json` | Descartar a sessão, refazer com modo fixo. |
| Build concorrente / IDE indexando | Picos no p95 de uma sessão; CV alto no §6.1 | Refazer a sessão após fechar o processo intruso. |
| `rustc` diferente entre sessões | Campo `toolchain.rustc` divergente | Descartar as divergentes; todas as sessões devem usar o mesmo compilador. |
| Harness não implementa `--warmup`/`--seed` (§2.6 não feito) | Falha de parse do argumento | **Não prosseguir** com o protocolo como escrito; recuar para a variante de pós-processamento e declarar. |
| Uma sonda adversarial dá veredito diferente entre sessões | Linha com `pass` variando em `adversarial.csv` entre sessões | Investigar não-determinismo antes de reportar; não mascarar com média. |
| Alteração de código entre a etiqueta e a execução | `git status` não-vazio no início da sessão | Abortar; a execução precisa vir de um estado publicado e imutável. |
| `numpy`/`scipy` indisponíveis no agregador | `ImportError` no §5 | Reescrever o agregador com `random` da biblioteca padrão; **não** trocar *bootstrap* por normal sem justificar. |
| Poucas sessões passam no critério de CV (§6.1) | Mais de uma sessão descartada, k < 4 | Aumentar k declarando **antes** de medir; nunca após ver o resultado. |

---

## 9. Resumo de execução (sequência de um parágrafo)

Limpar e tagear a `main` (§1); compilar antecipado (§1.4); estabilizar o *host*
(§1.5); para cada uma das 5 sessões: coletar metadados (§3), esperar 5 min,
executar o harness com `--iterations 2000 --warmup 200 --seed SEED_NN` (§4);
agregar com *bootstrap* de 10.000 reamostragens sobre as médias de sessão e IC
de Wilson para o adversarial (§5); verificar critério de aceitação (§6);
atualizar tabelas, figura, hashes e prosa da tese (§7); publicar a etiqueta só
depois de tudo consistente.
