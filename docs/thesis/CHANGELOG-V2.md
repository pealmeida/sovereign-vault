# CHANGELOG-V2 — integração das medições v2 em paper.tex

Formato: seção — o que mudou — id(s) em `numeros_autorizados.csv`.

- Preâmbulo — adicionado `\usepackage{multirow}` (exigido por `tab:pii-robustez`; `booktabs` já presente) — n/a.
- Resumo (PT) — adicionados os resultados que sobreviveram: gate de consentimento indistinguível de zero nos 6 contrastes; escopos ~2,1 µs com 20 escopos; cobertura 5/20 → 17/20; declarada a exclusão da escrita de auditoria; todos os caveats existentes mantidos — E1.diff.*, E3.scope20.*, E5.cov.old, E5.cov.new.
- Abstract (EN) — espelho da mudança do resumo — E1.diff.*, E3.scope20.*, E5.cov.old, E5.cov.new.
- §3 (eq. do gateway) — "enforce_scopes exercido na bateria" → "medido separadamente no WebSocket (Seção custo-escopos)" — E3.scope20.*.
- §3 `tab:metodologia-microbenchmark` — linha N atualizada para o protocolo corrigido (k=10, n=1000, 200 warmup descartadas, ordem aleatorizada, mediana+bootstrap); linha "Não medido" passa a apontar a medição WS de escopos e declara a escrita de auditoria excluída — E1.diff.* (protocolo), E3.scope20.*.
- §4.1 `tab:fronteira-evidencia` — linha "Redução de PII" ganha recall canônico 100% e FP 0% com remissão a `tab:pii-robustez`; linha "Sobrecarga local" passa ao protocolo corrigido e declara exclusão do audit-write; nova linha "Custo de escopos"; linha "Resultado adversarial" ganha extensão 24 sondas, 11/12 e 17/20 — E4a.recall, E4a.fp, E3.scope20.*, E3.scope1.128, E5.match, E5.cov.new.
- §4.1 — novo parágrafo declarando a limitação de instrumentação: `StageTimings.total` soma validate+authorize+execute+filter e nunca conta a escrita de auditoria pré-execução; custo não medido; quinto estágio em trabalhos futuros — n/a (limitação, sem número).
- §4.2 — Tabela 5 antiga (médias por modo, 12 células) removida e números retirados; substituída por `tab:latencia-pareada-v2` — E1.diff.128.APP, E1.diff.128.OTP, E1.diff.1k.APP, E1.diff.1k.OTP, E1.diff.16k.APP, E1.diff.16k.OTP.
- §4.2 — prose reescrita em três alegações: (1) custo do gate de consentimento indistinguível de zero (E1.diff.*); (2) ordenação publicada é artefato de medição de origem não determinada, números retirados, com lacuna de proveniência (E2.prov.diff, E2.prov.meta, E2.armA.median); (3) média é estatística errada: inversão falsa +6,005 µs pela média vs −0,032 µs pela mediana em 16 KiB, cauda direita p99 38,5–61,7 µs vs mediana ~29 µs (E1.P2.mean.16k.OTP, E1.P2.p99.direct.16k, E1.diff.16k.OTP).
- §4.2 — nota metodológica: células publicadas não eram ruído amostral (teste de sinais p=0,016; Cantelli 11,7–58,5 EP) — T5.signtest, T5.cantelli.
- §4.2 — inserida `tab:ablacao-ordem` com nota de identificabilidade intacta e `figuras/ablacao_ordem.png` — E2.wrongsign.A, E2.wrongsign.B, E2.wrongsign.C, E2.wrongsign.D.
- §4.2 — efeito de posição reformulado: atribuição linear não testável sob ordem fixa (colinearidade célula×posição); padrão observado (inversão concentrada em 128 B) favorece efeito categórico de estado frio; sem "REFUTADO" e sem o ~9% — SUP.pos (eliminado por reformulação), E2.armA.median (nota "ambos em 128 B").
- §4.2 (Figura 4) — TikZ de barras empilhadas (dados retirados) substituído por `figuras/figura4_corrigida.png`; legenda declara estimador (mediana), k=10, n=1000 e bootstrap percentílico B=10 000 por sessão — E1.diff.* (protocolo).
- §4.3 (nova seção "Custo de Imposição de Escopos no Caminho WebSocket") — inserida `tab:enforce-scopes` com nota do delta negativo intacta; prosa reporta +2,106/+2,102/+2,231 µs (IC excluindo zero) e o caveat −0,454 µs — E3.scope20.128, E3.scope20.1k, E3.scope20.16k, E3.scope1.128.
- §4.4 (Bateria) — nova subseção de cobertura: 5/20 → 17/20, três ferramentas nomeadas sem cobertura; inseridas `tab:cobertura-sondas` e `figuras/cobertura_sondas.png`; A11–A15 contra o binário real como subprocesso; 11/12 vereditos pré-especificados; cadeia HMAC verificada; sem taxa percentual — E5.cov.old, E5.cov.new, E5.match, E5.audit.
- §4.4 — nova subseção "Defeito Revelado pela Sonda C4": enforce_scopes nega incondicionalmente vault.info/export_agents/import_agents para agente escopado em headless; veredito congelado antes da execução; argumentado como contribuição do desenho da avaliação — E5.match (o mismatch é C4).
- §5.1 (Síntese) — referências atualizadas para as tabelas novas; 2,1 µs de escopos; cobertura 5/20 → 17/20 — E1.diff.*, E3.scope20.*, E5.cov.*.
- §5.2.1 (QP1) — "não há medição de precisão ou recall" substituído por recall canônico 100% (200/200) e FP 0% (0/500) por categoria — E4a.recall, E4a.fp.
- §5.2.2 (QP2) — reescrita: gate de consentimento zero; escopos 2,1 µs; exclusão do audit-write; (a) robustez por categoria com `tab:pii-robustez` (checksum robustas vs sintaxe fixa 0%, +55 detectado) — E4b.robust, E4b.strict; (b) densidade responde por 63,7% da inclinação marginal (R²=0,99979) — E4c.share; (c) validação cruzada 97,0% (7,395 vs 7,626 ns/B) e enunciado publicável: 7,63 ns/B é o pior caso, sem PII custa 2,68 ns/B = 36,6% — E4c.xcheck, E4c.slope.d1, E4c.slope.d0, E4c.pct.
- §5.2.3 (QP3) — acrescentada extensão da bateria: 5/20 → 17/20, A11–A15 contra binário real, 11/12, remissão ao defeito C4 — E5.cov.*, E5.match, E5.audit.
- §5.4 (Limitações) — evidência de desempenho atualizada para o protocolo corrigido; exclusão do audit-write declarada; escopos medidos à parte com ressalva de ordem fixa; bateria: A11–A15 no binário real, 3 ferramentas sem cobertura nomeadas; recall/FP medidos em identificadores sintéticos — E1.diff.*, E3.*, E5.*, E4a.*.
- §5.5 (Trabalhos Futuros) — "primeira prioridade" (execução definitiva) marcada como realizada para latência; novas prioridades: quinto estágio StageTimings para audit-write, metadados por sessão, aleatorizar braços de escopo; correção do defeito C4 e cobertura das 3 ferramentas restantes — E3.scope1.128, E5.cov.new.
- Apêndice — adicionado parágrafo apontando `docs/thesis/evidence/v2/`, `numeros_autorizados.csv`, relatório e auditoria; registrada a lacuna de proveniência da tabela retirada (sem run-metadata.json; harness reescrito, commit 2fb252b) — E2.prov.diff, E2.prov.meta.

## Valores supersedidos — varredura

Grep por `7/20`, `35%`, `35 \%`, `sete das vinte`, `7,4`, `0,375`, `~9`/`9%` em toda a árvore `.tex` (paper.tex, paper-uspsc.tex, USPSC-*.tex, uspsc/_body.tex): **nenhuma ocorrência dos quatro valores supersedidos existia no texto publicado**. A versão corrente do paper nunca chegou a incorporar densidade 7,4%, robustez uniforme 0,375, efeito de posição ~9% ou cobertura 7/20 — esses valores circularam apenas em rascunhos externos ao repositório. Nada a remover; apenas integração dos valores corretos.

## Não inserido (decisões)

- `identificabilidade_posicao.png` — opcional pelo briefing; a nota de rodapé de `tab:ablacao-ordem` carrega a ressalva de identificabilidade.
- `pii_recall.png` — sem posicionamento mandatório no briefing; `tab:pii-robustez` cobre o conteúdo.
- Correções (b)/(c) do §5.2.2 são reportadas como resultados novos, sem referência a "rascunho anterior": as alegações erradas (varredura domina; qualificação favorável antiga) nunca constaram deste paper.tex.
