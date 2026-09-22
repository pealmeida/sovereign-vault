**VEREDITO DE ENVIO: NÃO LIBERADO.**

O HEAD `40fdb358c` incorpora a maior parte das correções, mas ainda contém afirmações que os pareceres mandaram retirar e uma contradição introduzida pela declaração de IA. Os bloqueios são textuais e corrigíveis sem novas medições.

Nenhum arquivo do repositório foi alterado; não houve commit ou push. Sincronização, compilação e testes ocorreram em cópia temporária do HEAD. `origin/main` local coincide com HEAD.

Nas tabelas, os caminhos sem prefixo são relativos a `docs/thesis/`. **R1/R2** designam as duas rodadas adversariais.

**Verificação das revisões**

| Item | Estado | Evidência no HEAD |
|---|---|---|
| R2, ação 1/B1: travessões da orientadora | **APLICADO** | Os dez delimitadores nos oito trechos estão preservados em `paper.tex:345,353,358,361,363,421,467,474`. Restauração em `3e3b51320`. |
| Demais intervenções da orientadora | **APLICADO** | Comparação com `9e8d95e9a`: estrutura dos cinco capítulos, chamadas passivas alteradas por ela, itálicos e `scalefnt` preservados. As instruções provisórias de redação foram preenchidas. Não encontrei reversão adicional das intervenções examinadas. |
| R1-B1: contagem da alteração do harness | **APLICADO** | `paper.tex:512` e `evidence/v2/numeros_autorizados.csv:16`: 227 inserções + 38 remoções = 265. Confirmado com `git show --numstat 2fb252b`. |
| R1-B2: percentual sem PII | **APLICADO** | `paper.tex:724` e registro:30 usam 35,2%; compatível com `100 × 2,683 / 7,626`. |
| R1-A1/R2-B2: Cantelli e teste de sinais | **PARCIAL** | A nota foi substituída corretamente em `paper.tex:539`. Entretanto, o registro:35–36 conserva as interpretações antigas sem a ressalva explícita solicitada; `CHANGELOG-V2.md:14` ainda afirma causa não amostral. |
| R1-A2/R2-B3: média versus mediana | **PARCIAL** | Substituto aplicado em `paper.tex:537`; ressalva de não equivalência em :533. O registro:8 ainda chama o resultado da média de “inversao FALSA”. Resumo, abstract e QP2 (:140,145,693) mantêm a síntese ampla “custo […] indistinguível de zero”, sem explicitar ali o estimando. |
| R2-B3: impossibilidade causal da ordenação | **PARCIAL** | Legenda corrigida em `paper.tex:545`, mas :512 ainda afirma que a ordenação “não pode ser um efeito causal”, precisamente a formulação cuja retirada foi pedida. |
| R1-A3/R2-B3: escopos e ordem fixa | **APLICADO**, com resíduo | Texto e nota corrigidos em `paper.tex:589,610`; resumo/abstract/QP2 qualificados em :140,145,693. Em :776, porém, permanece a atribuição “ordem fixa produziu o delta negativo”. |
| R1-M1: uma sessão versus dez sessões | **PARCIAL** | Distinção correta em `paper.tex:266,423,750`. O checklist ainda apresenta “1 sessão” e IC ausente em :311–312, sem incorporar ali o estado v2. |
| R1-M2/R2-B4: taxonomia e errata | **APLICADO** | `probe_taxonomy.csv:2–11` contém `BLOCKED,BLOCKED`. Os brutos permanecem intactos. A mensagem de `3e3b51320` registra expressamente a errata de transcrição. |
| R1-M3: estimador entre sessões | **PARCIAL** | Definição correta na tabela, `paper.tex:516`. Metodologia :465 e legenda da figura :579 continuam usando apenas “mediana por célula”, sem explicitar a agregação entre sessões solicitada. |
| R1-M4: cobertura da CI | **PARCIAL** | `.github/workflows/ci.yml:186` confere sincronização, mas :201–205 compila somente `paper.tex`. As duas variantes foram verificadas localmente nesta revisão; isso não amplia a CI. |
| R1-M5: retorno do verificador | **APLICADO** | `scripts/check-thesis-citations.py:52` retorna código 1 quando encontra problemas. |
| R1-M6/R2-M6: ordem das referências | **APLICADO** | As 27 entradas de `paper.tex:792` em diante coincidem exatamente com a ordem de primeira citação. |
| R1-M7/R2-M7: legendas acima | **APLICADO** | Seis de seis figuras possuem legenda antes da imagem: `paper.tex:296,322,370,567,579,665`. |
| R1-M8: comando de metadados | **PARCIAL** | Chamada corrigida em `EXECUCAO-DEFINITIVA.md:342`, incluindo `"$POWER_MODE"`. O bloco ilustrativo anterior, :271, ainda documenta a assinatura antiga; o exemplo não define essa variável. |
| R1-L1: referência do mascaramento | **APLICADO** | `paper.tex:351` aponta para `crates/sv-mcp/src/lib.rs:1431–1466`. |
| R1-L2/R2-B3: alcance de DIRECT | **PARCIAL** | Leituras e gestão distinguidas em `paper.tex:266,351`. A generalização “Contêineres DIRECT dispensam consentimento” permanece em :765. |
| R1-L3: anos de Nisa e Şakar | **APLICADO** | `paper.tex:792,801`: março/2026 e janeiro/2025. |
| R1-L4/R2, achados baixos: presente e organização | **APLICADO** | Fechamentos em `paper.tex:276,480,744`; abertura de conclusões em :747. |
| R1-L5/R2, siglas e itálicos | **APLICADO** | MCP corrigido em :140; reexpansões de DSR/RAG retiradas em :280,314; novos usos de contêineres corrigidos em :351. |
| R2-A4: limites operacionais de E1 | **APLICADO** | `paper.tex:771` registra as dez sessões em 22 segundos e a ausência de controle de energia; :776 preserva a necessidade de nova execução controlada. |
| R2-A5: descrição da figura de latência | **APLICADO** | `paper.tex:575` descreve corretamente os dois painéis, sem prometer bigodes p95 ou decomposição de estágios. |
| R2-B5: parágrafo e números v3 | **APLICADO** | `paper.tex:769`; nove entradas `E6.ext` em registro:37–45. Recontagem: 48 casos, incluindo oito controles; 14 acertos canônicos. |
| R2, ação 3: proveniência v3 e âncora | **PARCIAL** | Âncora de código explícita em `paper.tex:825`, resolvendo para `ec3bd73ec`. Limites de reprodução v3 em :769. Falta a remissão explícita, no apêndice, ao manifesto v3 e aos SHAs de medição E1/v3 solicitados. |
| R2-A6: LORENZON e KLEPPMANN | **APLICADO** | `paper.tex:802`: título completo, periódico correto, v. 1, p. 39–52; :798: p. 154–178. Correspondem às correções documentadas no parecer. |
| R2-A7: ANONYMIZED no modelo de ameaça | **APLICADO** | `docs/threat-model.md:114` distingue mascaramento implementado dos modos reservados. |
| R2-M8: árvore das citações de código | **APLICADO** | `paper.tex:825,847`; etiqueta anotada existente. As 14 faixas também existem nessa árvore, não apenas em main. |
| R2-M9: barra em `sv_privacy` | **APLICADO** | `paper.tex:769` usa `\codigo{sv_privacy::redact}`. |
| R2: densidade saturada e “pior caso” | **NÃO APLICADO** | `paper.tex:724` ainda trata concordância de inclinações como confirmação da composição antiga e como caracterização do pior caso. |
| R2, ação 5: checklist atualizado | **PARCIAL** | Nota histórica e algumas contagens atualizadas em `CHECKLIST-ENTREGA.md:6`. Permanecem ficha ausente (:43,362), declaração de IA pendente (:263), uma sessão/IC ausente (:311–312) e paginação antiga (:3). |
| R2, ação 6: sincronização e compilação | **APLICADO** | Fragmentos do HEAD, checkout e regeneração temporária coincidem byte a byte. Ambas as variantes compilam. |
| R2, ação 7: ficha e procedimentos finais | **PARCIAL** | Ficha inserida e paginação coerente. Procedimento de banca não está comprovado; os campos continuam em aberto. |
| R2-B6: permissões dos cinco scripts | **APLICADO** | Cinco modos `100755`, restaurados por `9b3b65e00`. |
| Veredito separado de fechamento do repositório | **NÃO SE APLICA** | Esta tarefa é revisão de envio; não certifiquei CI remota, merge ou encerramento de PRs. |

**R16 e respostas prometidas**

O código atual evoluiu além da implementação descrita na resposta. Isso precisa ser distinguido de descumprimento do requisito de privacidade.

| Achado | Estado | Evidência |
|---|---|---|
| R1: evitar exposição de nomes/OTP | **PARCIAL** documentalmente | O código é ainda mais restritivo: texto fixo, sem campos da requisição, em `apps/desktop/src-tauri/src/lib.rs:702–711`. Porém, `docs/adr/0014-os-notifications-for-consent-prompts.md:31,66` ainda descreve envio do nome da ação; o modelo de ameaça não conserva o parágrafo de notificações prometido. |
| R2: notificações obsoletas | **NÃO APLICADO** ao estado atual | ADR:52–55 afirma retirada no Linux. O código atual usa o plugin e descarta o resultado de `show()` em `lib.rs:793–798`; não há ali o ciclo de cancelamento descrito. A limitação prometida não está corretamente documentada para esse estado. |
| M1: explicitar entrega best-effort | **PARCIAL** | Comportamento preservado por `let _ = ...`, mas o helper e o comentário pontual descritos na resposta foram substituídos. ADR:41 mantém o contrato. |
| M2: truncamento de nomes | **NÃO SE APLICA** | O corpo atual é constante; não concatena nomes. |
| M3: distinguir OTP por modo/segredo | **NÃO SE APLICA** | `notification_text` deixou de existir; a notificação atual não distingue OTP. |

A resposta R16 é um registro histórico, não uma descrição fiel de todo o HEAD atual.

**Cinco commits finais**

| Commit | Estado | Conferência |
|---|---|---|
| `2e5629aaf` — declaração de IA | **PARCIAL** | As duas cópias têm conteúdo idêntico e 16 opções. Nível 3 e ferramentas estão presentes. Entretanto, `paper.tex:944–947` afirma incorretamente que o corpus adicional está versionado. Data e assinatura estão vazias em :965–968. |
| `210ca545a` — URL e árvore | **APLICADO** | URL em `paper.tex:218,825`; [repositório público acessível](https://github.com/pealmeida/sovereign-vault). Etiqueta anotada resolve para o SHA declarado. |
| `81635a83e` — ficha A447a | **APLICADO** | `paper.tex:71–80`; inclusão do PDF oficial em `paper-uspsc.tex:93`. Autor, título, orientadora, ano e 65 páginas concordam. |
| `a21ed4800` — PDF final | **APLICADO** | PDF versionado atualizado, posteriormente recompilado no último commit; corresponde ao conteúdo atual. |
| `40fdb358c` — GPT/Codex | **APLICADO** | `paper.tex:904`, cópia do formulário, fragmento USPSC e PDF usam “GPT/Codex (OpenAI)”. |

**Verificações executadas**

| Verificação | Resultado |
|---|---|
| Sincronização USPSC | Sem divergências em relação aos fragmentos versionados. |
| `latexmk -pdf`, canônica | 67 páginas físicas; último número 65; zero erros e zero referências/citações indefinidas. |
| `latexmk -pdf`, USPSC | 67 páginas físicas; último número 65; zero erros e zero referências/citações indefinidas. |
| Correspondência do PDF entregue | Texto das 67 páginas coincide após normalizar espaços/hífens; cinco imagens embutidas idênticas. Há diferenças de composição na recompilação, não de conteúdo identificado. |
| Ficha catalográfica | Na página física 4; “65 p.” corresponde à última página numerada. **67 físicas versus 65 numeradas não é inconsistência.** |
| Citações de código | Verificador aprovado: 14 faixas, nenhuma inválida. Isso verifica alcance, não toda a semântica das citações. |
| Figuras/tabelas/equações | 6/10/2; nenhuma sem referência textual. |
| Integridade da evidência | Três hashes do apêndice conferem; quatro arquivos do manifesto v3 conferem; brutos v2 preservados. |
| Testes | `cargo test --workspace --offline --locked`: 589 aprovados, zero falhas, quatro ignorados. Agregador: 14 aprovados. |

Há **um overfull horizontal de 6,24477 pt em ambas as variantes**, no parágrafo da URL (`paper.tex:825`). A canônica tem também **overfull vertical de 14,49998 pt**, pelo cabeçalho longo do Anexo A, visível na página física 66. A USPSC entregue não apresenta esse segundo problema. Há avisos de depreciação e caixas underfull; não encontrei texto cortado nas páginas inspecionadas.

A inspeção visual também identificou um resíduo menor: a **Figura 5** contém, dentro do PNG, o título “Figura 4 corrigida” (`paper.tex:581`).

**Bloqueios reais e correções propostas**

1. **Declaração de IA contradiz a proveniência.**  
   `paper.tex:944–947` e `USPSC-TA-PosTextual/USPSC-DeclaracaoIA.tex:93–96` dizem que todos os corpora estão versionados, incluindo o adicional. `paper.tex:769` e `evidence/v3/pii-externa/provenance.json:6–8` dizem que corpus/adaptador são externos.  
   **Correção:** declarar que estão versionados as observações, escores e proveniência; preservar explicitamente a dependência externa do corpus rotulado e adaptador.

2. **Persistem inferências expressamente rejeitadas.**  
   `paper.tex:512` conserva impossibilidade causal; :724 conserva confirmação de densidade saturada e “pior caso”; :776 atribui o delta à ordem fixa.  
   **Correção:** aplicar as formulações descritivas já propostas na rodada 2, sem mudar números: causa não identificada, densidade máxima **testada**, efeitos de escopo e posição não separados.

3. **A retirada das interpretações não foi propagada ao registro de evidência.**  
   `evidence/v2/numeros_autorizados.csv:8,35–36` mantém “inversão FALSA” e interpretações inferenciais sem a ressalva solicitada.  
   **Correção:** preservar os valores históricos e marcar explicitamente as interpretações como retiradas; harmonizar resumo/abstract/QP2 com o contraste entre medianas e a ausência de teste de equivalência.

Como pendências de fechamento, atualizar o checklist e o ADR-0014; datar/assinar a declaração conforme o procedimento exigido. Os placeholders `[MEMBRO DA BANCA 1/2]` permanecem em `paper-uspsc.tex:124,128`: **não os classifico como bloqueio incondicional sem saber se o envio é pré-defesa ou depósito definitivo**.

Não encontrei `[CONFIRMAR]`, TODO ou “A GERAR” impressos no PDF. Não certifiquei antiplágio, autorização institucional para folha de aprovação incompleta ou execução experimental definitiva. A reconsulta online de LORENZON/Crossref não foi concluída por indisponibilidade dos endpoints; a aplicação das correções bibliográficas foi conferida contra os pareceres fornecidos.