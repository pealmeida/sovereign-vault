# Resposta ao parecer R15 — fechamento de integridade

Data: 2026-08-04
Parecer: `R15-fechamento-integridade-glm52.md`

## Veredito e adjudicação

O veredito de aprovação para commit foi aceito. O achado relevante sobre
`Linux 7.0` foi confirmado: o valor não corresponde a uma versão preservada na
captura e não pode permanecer como metadado. Ele foi removido de `paper.tex`,
`EVALUATION.md` e `EVOLUTION.md` sem substituição especulativa; os três arquivos
passam a declarar explicitamente que a versão do núcleo não foi preservada.

O achado menor sobre HITL foi rejeitado após varredura direta do estado
revisado. A primeira ocorrência da sigla no corpo está em `paper.tex:432` e já
introduz “humano no circuito (*Human-in-the-Loop* — HITL)”. A ocorrência
indicada pelo parecer como anterior não existe no arquivo corrente.

A auditoria tipográfica foi repetida por busca das expressões estrangeiras
recorrentes. Não foram alterados termos apenas para uniformização cosmética;
as ocorrências substantivas permanecem em `\textit{}` ou em comandos de código.

## Verificação posterior às correções

As verificações foram reexecutadas depois deste fechamento:

- sincronização com 27 citações, 27 entradas e zero órfãs;
- três passadas de `pdflatex` nas duas variantes, sem erros, referências
  indefinidas, caixas `overfull`, grupos abertos ou conteúdo descartado;
- inspeção visual da tabela nas duas variantes, sem perda de legibilidade,
  extrapolação de margem ou sobreposição;
- `cargo test --workspace` com zero falhas.
