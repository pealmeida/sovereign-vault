# Resposta consolidada aos pareceristas — R13 e R14

## Síntese editorial

Os dois pareceres independentes aprovaram sem bloqueantes a tabela de
posicionamento funcional e os ajustes em Trabalhos Correlatos, Confronto e
Contribuições. A revisão de segurança identificou, contudo, que a analogia de
negação por padrão entre HAMSTER e Sovereign Vault excedia o código: em
`enforce_scopes`, escopos vazios significam superfície irrestrita, ainda sujeita
ao modo do contêiner. Nenhum número, resultado experimental ou capacidade foi
acrescentado nesta rodada.

## R13 — metodologia/DSR e integridade de alegações

1. **[ACEITO — CORRIGIDO APÓS CONFIRMAÇÃO DO AUTOR]** `TRACEABILITY.md` foi
   alinhado à QP3 e ao objetivo de avaliação atuais: sem isolamento no nível do
   SO e sem comparação com nuvem executada.
2. **[ACEITO — CORRIGIDO APÓS CONFIRMAÇÃO DO AUTOR]** A contagem de ferramentas
   foi revalidada em `base_tool_descriptors` e nos testes de `tools/list`:
   17 ferramentas-base e três condicionais de broker.
3. **[ACEITO]** A força do precedente HAMSTER foi alinhada à formulação
   cautelosa “arquitetura acompanhada de estudos de caso avaliativos”. A página
   oficial da Springer confirma que o artigo apresenta dois estudos de caso,
   incluindo avaliações de esquemas de comunicação e de algoritmos de curvas
   elípticas.
4. **[ACEITO — CORRIGIDO APÓS CONFERÊNCIA]** McMahan et al. (AISTATS 2017) foi
   incluído como âncora primária de Aprendizado Federado; a entrada incorreta de
   `arXiv:2101.05428` foi corrigida para Priyanka Mary Mammen conforme o arXiv.
5. **[NÃO APLICADO]** Não se afirmou ausência de *prior art* próximo, pois o
   recorte não é revisão sistemática e não sustenta uma negativa universal.
6. **[ACEITO]** A linha do Sovereign Vault foi limitada ao caminho WebSocket
   autenticado e passou a distinguir modelo, método e instanciação DSR.
7. **[ACEITO — CORRIGIDO APÓS CONFIRMAÇÃO DO AUTOR]** A tabela rápida de
   `PUBLICACOES-KALINKA-LINKS.md` foi corrigida de 2017 para 2016, conforme a
   fonte oficial e o `paper.tex`.

## R14 — segurança e fronteira conceitual

1. **[ACEITO — CORRIGIDO]** A redação deixou de transpor negação por padrão do
   HAMSTER como se fosse o mesmo modelo no Sovereign Vault. O texto agora
   explicita que chamadas fora da concessão são negadas somente para agentes com
   escopos definidos; escopos vazios significam superfície irrestrita ainda
   sujeita ao modo do contêiner.
2. **[ACEITO — CORRIGIDO]** A célula de comportamento padrão separa autorização
   por escopo, consentimento em APPROVAL/OTP e ausência deliberada de aprovação
   em DIRECT/ANONYMIZED.
3. **[ACEITO]** O confronto remete explicitamente ao modelo de ameaça de usuário
   único e máquina única e exclui isolamento de processo/SO.
4. **[ACEITO]** A legenda registra que as naturezas de evidência não são
   diretamente comparáveis, evitando leitura de ranking.
5. **[ACEITO]** A assimetria da evidência permanece explícita: o precedente é
   descrito por estudos de caso avaliativos, enquanto esta instanciação mantém a
   qualificação artificial, somativa, preliminar, de uma sessão e sem IC.

## Verificação executada após as respostas

- `scripts/sync-uspsc-body.py`: 27 citações, 27 entradas e zero órfãs.
- Três passadas de `pdflatex` em `paper.tex` e `paper-uspsc.tex`: zero erros,
  referências indefinidas ou caixas `overfull` nos logs.
- Renderização e inspeção visual da página da nova tabela nas duas variantes:
  texto legível, margens preservadas e ausência de sobreposição.
- `cargo test --workspace`: concluído com sucesso, zero falhas.

Os pareceres R13 e R14 não editaram o artefato nem realizaram essas verificações;
as correções, a compilação e os testes foram executados na etapa de resposta.
