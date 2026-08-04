# Pacote USPSC 3.2 — arquivos de terceiros

Este diretório contém arquivos **de terceiros**, redistribuídos sem modificação.
Nada aqui é de autoria do trabalho; não editar.

## Procedência

| Campo | Valor |
|---|---|
| Pacote | USPSC — Modelos de trabalhos acadêmicos em LaTeX, versão 3.2 |
| Origem | Biblioteca da Prefeitura do Campus USP de São Carlos |
| Download | <http://biblioteca.puspsc.usp.br/wp-content/uploads/2024/02/USPSC-3.2.zip> |
| Página oficial | <http://biblioteca.puspsc.usp.br/index.php/pacote-uspsc-modelo-para-teses-e-dissertacoes-em-latex/> |
| Obtido em | 04/08/2026 |
| Base | derivado de `abntex2.cls` v1.9.5 |

## Licença

Os arquivos `.bst` declaram a **LaTeX Project Public License (LPPL), versão 1.3**
— <http://www.latex-project.org/lppl.txt> —, que autoriza redistribuição. A
classe `USPSC.cls` traz o aviso de copyright do grupo abnTeX2 (2012–2015) e
herda a mesma licença por derivação.

Manutenção do pacote: equipe da PUSP-SC (coordenação de Marilza Aparecida
Rodrigues Tognetti e Ana Paula Aparecida Calabrez), com normalização por
bibliotecários das Unidades do campus. Os créditos completos estão nos
cabeçalhos dos próprios arquivos.

## Por que está versionado

A compilação da variante `../paper-uspsc.tex` precisa da classe, e o CI não tem
acesso à rede para baixá-la no momento do build. Versionar 400 KB garante que a
monografia compile de forma reprodutível a partir de um *checkout* limpo — o
mesmo critério de reprodutibilidade que o Capítulo 4 exige da evidência.

## Conteúdo

| Caminho | O que é |
|---|---|
| `USPSC-classe/USPSC.cls` | classe principal (cabeçalho só com número de página) |
| `USPSC-classe/USPSC1.cls` | variante com cabeçalho distinto em páginas pares/ímpares |
| `USPSC-classe/ABNT6023-10520.sty` | compatibilização NBR 6023:2018 e 10520:2023 — **não carregado** por exigir `abntex2cite`; ver o comentário em `../paper-uspsc.tex` |
| `USPSC-classe/*.bst` | estilos BibTeX (alf/num, PT/EN) — para uso futuro, se houver migração para `.bib` |
| `_body.tex`, `_pretextual-conteudo.tex` | **gerados** por `scripts/sync-uspsc-body.py` a partir de `../paper.tex`; ignorados pelo git |

Os arquivos `USPSC-unidades.tex`, `USPSC-pre-textual-ICMC.tex` e
`USPSC-TCC-pre-textual-ICMC.tex` ficam em `../` (raiz de `docs/thesis/`) porque a
classe os carrega por `\include` sem prefixo de caminho.

## Atualizar o pacote

Baixar a versão nova, substituir os arquivos, e recompilar as duas variantes
conferindo que ambas seguem com 0 erros e 0 citações/referências indefinidas.
