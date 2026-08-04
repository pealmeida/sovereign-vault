# Revisão estrutural e conceitual — monografia × obras da orientadora

**Data:** 04/08/2026
**Insumos:** leitura integral de três obras da Profa. Kalinka (PDFs fornecidos
pelo autor) confrontada com o `paper.tex` completo.
**Complementa:** [`PONTOS-DE-APOIO-TESE.md`](PONTOS-DE-APOIO-TESE.md) (plano
P1–P5) e [`PUBLICACOES-KALINKA-LINKS.md`](PUBLICACOES-KALINKA-LINKS.md).
**Status:** inserções P1, P2, P4 e P5 e tabela de posicionamento funcional
**aplicadas** ao `paper.tex`; paginação de HAMSTER conferida na fonte primária;
variante USPSC sincronizada; ambas as variantes recompiladas e inspecionadas.

---

## 1. O que cada obra sustenta na monografia

### 1.1 HAMSTER (Pigatto et al., *J. Intell. Robot. Syst.*, 2016) — forma e conceito

Lida na íntegra. Conceitos com correspondência **estrutural direta** no
Sovereign Vault:

| HAMSTER/Sphere | Sovereign Vault | Onde no `paper.tex` |
|---|---|---|
| CSU (Central Security Unit): ponto único que autentica módulos antes da operação | Gateway MCP: autentica agentes antes de qualquer operação | §3.6.2, Fig. fluxo |
| Postura *almost deny all*: nenhum componente é autêntico até prova em contrário | Correspondência apenas parcial: agentes com escopos definidos têm chamadas fora da concessão negadas; escopos vazios significam superfície irrestrita sujeita ao modo, e a sonda A8 é bloqueada pelo modo | §3.7, §4.3, Tabela de sondas |
| Categorização de módulos por criticidade (primário/secundário) com tratamento graduado | Modos de contêiner DIRECT/APPROVAL/OTP/ANONYMIZED como mediação graduada por sensibilidade | §3.6.3 |
| Perfis de acesso por usuário (analogia admin/visitante) | Escopos de capacidade por agente | §3.7 |
| CSU guarda tabela de chaves públicas (opera como CA local) | Keyring lista chaves de trânsito/assinatura retornando só chave pública | nota *headless* |
| Falha em módulo primário → veículo não opera (*fail-closed*) | Correção *headless fail-closed* para operações secretas *modeless* | nota *headless* |

**Aplicado:** parágrafo novo em §2.6 (Trabalhos Correlatos) descrevendo
Sphere/CSU, autenticação prévia e criticidade graduada, com a transposição
explícita e a **adjacência honesta** ("estrutural, não de domínio"). A redação
também distingue os modelos de falha: a negação por padrão de HAMSTER não foi
atribuída aos escopos vazios do Sovereign Vault. A frase em §5.4 ancora a
*forma* da contribuição no precedente, descrito como arquitetura acompanhada de
estudos de caso avaliativos. `\bibitem{pigatto2016}` acrescentado.

### 1.2 Avaliação criptográfica (Silva et al., *JNCA*, 2016) — método

Lida na íntegra. É o precedente metodológico mais forte:

- Método de Jain (1991): variável de resposta, fatores, níveis, **desenho
  fatorial completo**, análise de influência de fatores (ex.: no caso AES,
  tamanho da mensagem respondeu por 89% do efeito, chave 10%, interação 1%).
- O microbenchmark da monografia **já é** um fatorial completo 4 modos × 3
  cargas — só não se apresentava com esse vocabulário.
- O achado da monografia (filtro de PII domina ANONYMIZED em 16 KiB) tem o
  mesmo formato analítico do achado deles (fator dominante identificado e
  quantificado). A execução definitiva pode fechar esse ciclo calculando a
  influência percentual de cada fator.

**Aplicado:** abertura de §3.10.1 filia o desenho do microbenchmark à tradição
de Silva et al. e nomeia o fatorial completo; §5.6 (Trabalhos Futuros) ganha a
análise de influência de fatores como extensão da execução definitiva.
`\bibitem{silva2016}` acrescentado.

### 1.3 Táxis aéreos: *security* & *safety* (Ferrão et al., *Sensors*, 2022) — fronteira conceitual

Lida na íntegra. Tese central: arquiteturas projetadas para *safety* podem ter
lacunas de *security* e vice-versa; só 3 trabalhos da literatura tratavam as
duas em conjunto; é preciso projetá-las juntas. Correspondência com a
monografia:

- A distinção mascaramento técnico × anonimização jurídica (Art. 5º LGPD) é um
  caso da mesma lição: **propriedades de famílias distintas não se implicam**.
- O texto da revisão também registra que só um estudo mencionava cifragem — o
  mesmo tipo de lacuna que a monografia aponta na mediação de agentes.

**Aplicado:** §5.5 (Limitações) ganhou o espelhamento explícito citando
`\cite{ferrao2022}`, ligando *safety*×*security* à distinção técnica×normativa
que o texto já fazia. `\bibitem{ferrao2022}` acrescentado.

### 1.4 P5 (enquadramento de governança) — aplicado sem citação

Frase de ancoragem adaptada inserida em §1.2, conforme o plano (enquadramento,
não citação): soberania individual como o análogo, em outra escala, da
governança de dados sob custódia institucional.

---

## 2. Achados estruturais (além das citações)

1. **§2.6 era o ponto mais fraco** — um parágrafo cobrindo só Aprendizado
   Federado e Solid, avaliado por uma orientadora que é autora de revisão
   sistemática. O parágrafo HAMSTER reduziu o problema, e a revisão seguinte
   acrescentou a Tabela de posicionamento funcional (FL × Solid ×
   HAMSTER/Sphere × Sovereign Vault). A tabela distingue etapa/objeto, ponto de
   controle, comportamento padrão pertinente e natureza da evidência, com
   ressalva explícita de que não constitui comparação experimental, ranking ou
   levantamento exaustivo.
2. **A estrutura geral do TCC já segue o padrão do grupo** (arquitetura
   nomeada → módulos → estudos de caso/medição → recomendações delimitadas).
   Nenhuma reorganização de capítulos é necessária.
3. **A revisão independente R14 corrigiu a analogia de negação por padrão.**
   HAMSTER é *fail-closed* de autenticação; no Sovereign Vault, escopos vazios
   representam superfície irrestrita e a contenção remanescente depende do modo
   do contêiner. A sonda A8 demonstra bloqueio por modo, não por escopo. A tabela
   e o confronto preservam a adjacência de forma sem equiparar modelos de falha.
4. **Vocabulário *safety*/*security*** agora aparece uma única vez, no ponto de
   maior retorno (§5.5). Evitou-se espalhá-lo — o domínio da monografia não é
   sistemas críticos veiculares.
5. **Rigor de qualificação**: o hábito da monografia de declarar "o que não se
   mede" é compatível com a conclusão da *Sensors* 2022 ("é impossível atingir
   segurança absoluta; falhas sempre existirão") — coerência epistêmica que
   pode ser citada na arguição, sem necessidade de novo texto.

## 3. O que deliberadamente NÃO foi feito

| Item | Motivo |
|---|---|
| P3 (IDS ICUAS 2023 na bateria adversarial) | Texto integral conferido; o trabalho avalia classificadores IDS contra ataques e conjuntos de dados, não uma bateria pré-especificada de chamadas MCP. A citação foi rejeitada para evitar analogia metodológica excessiva |
| Citações de UAV/VANT no corpo do domínio | Anti-padrão listado no plano: citação decorativa detectável |

## 4. Verificação

- `scripts/sync-uspsc-body.py`: 27 citações · 27 entradas · 0 órfãs.
- Três passadas de `pdflatex` em `paper.tex` e `paper-uspsc.tex`: ambos geram
  PDF, sem erros, referências indefinidas ou caixas `overfull` nos logs.
- A varredura dos logs também confirma ausência de grupos abertos e de conteúdo
  descartado após os três blocos `verbatim`, cujos fechamentos foram corrigidos.
- A página da nova tabela foi renderizada nas duas variantes e inspecionada:
  texto legível, margens preservadas e ausência de sobreposição.
- `cargo test --workspace`: concluído com sucesso, zero falhas.
- Dados bibliográficos conferidos contra os próprios PDFs (JNCA: v. 60,
  p. 130-143; *Sensors*: v. 22, n. 18, art. 6875). A paginação 705-723 do
  HAMSTER (JIRS v. 84) foi confirmada na página oficial da Springer Nature
  (<https://link.springer.com/article/10.1007/s10846-016-0356-x>).

## 5. Diff aplicado (resumo por âncora)

| Local | Inserção |
|---|---|
| §1.2 Justificativa | Frase de enquadramento governança↔soberania (P5, sem citação) |
| §2.6 Trabalhos Correlatos | Parágrafo HAMSTER/Sphere com transposição e adjacência honesta (P2) |
| §2.6 Trabalhos Correlatos | Tabela de posicionamento funcional das quatro abordagens, anunciada e interpretada no texto |
| §3.10.1 Avaliação de Latência | Filiação metodológica a Silva et al. + fatorial completo nomeado (P1) |
| §5.3 Confronto | Retomada da tabela e confronto explícito com HAMSTER sem equivalência de domínio ou comparação empírica |
| §5.4 Contribuições | Frase sobre a forma da contribuição citando HAMSTER (P2) |
| §5.5 Limitações | Espelhamento *safety*×*security* ↔ técnica×normativa citando Ferrão et al. (P4) |
| §5.6 Trabalhos Futuros | Análise de influência de fatores na execução definitiva (P1) |
| Referências | `ferrao2022`, `pigatto2016`, `silva2016` em ordem alfabética, padrão ABNT do arquivo |
