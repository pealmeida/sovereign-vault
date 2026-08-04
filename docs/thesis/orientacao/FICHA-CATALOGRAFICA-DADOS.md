# Ficha catalográfica — dados prontos para preenchimento

**Formulário:**
<https://www.icmc.usp.br/institucional/estrutura-administrativa/biblioteca/servicos/ficha>

É **formulário automatizado de autoatendimento** (gera o resultado na hora, sem
espera por bibliotecário). O `action` é `/ficha-catalografica/ficha.php` e a
saída pode ser pedida em PDF ou HTML.

> **Por que não foi submetido automaticamente:** submeter o formulário publica
> seus dados pessoais num sistema institucional da USP em seu nome. É ação
> externa e irreversível no registro da Biblioteca — decisão sua, não minha.
> Todos os valores abaixo já estão derivados do `paper.tex`; é digitação
> mecânica, cerca de 3 minutos.

---

## Valores campo a campo

Nomes de campo conforme o HTML do formulário.

| Campo | Valor |
|---|---|
| `nome` | `Pedro Henrique Almeida Prado` |
| `sobrenome` | `Oliveira` |
| `titulo` | `Arquitetura de Soberania de Dados para Agentes de IA Pessoais: Um Modelo Local-First Baseado em Protocolos Descentralizados` |
| `cutter` | usar a tabela de Cutter oferecida na própria página, a partir de **Oliveira** |
| `trabalho` | Monografia / Trabalho de Conclusão de Curso |
| `programa` | MBA em Inteligência Artificial e Big Data |
| `nome_ori` | `Kalinka Regina Lucas Jaquie` |
| `sobrenome_ori` | `Castelo Branco` |
| `orientadora` | marcar — a orientadora é do gênero feminino (muda a flexão para "Orientadora") |
| `nome_coori` / `sobrenome_coori` / `coorientadora` | deixar vazio (não há coorientação) |
| `ano` | `2026` |
| `pags` | **conferir no PDF final antes de gerar** — hoje 50 na variante USPSC, mas o número muda quando a ficha e os números definitivos entrarem |
| `assunto1` | `Soberania de dados` |
| `assunto2` | `Agentes de inteligência artificial` |
| `assunto3` | `Privacidade` |
| `assunto4` | `Local-First` |
| `assunto5` | `Model Context Protocol` |
| `exibicao` | PDF |

> **Atenção ao número de páginas.** Gerar a ficha **por último**, depois de
> inserir os números definitivos do Capítulo 4 — senão o total impresso na ficha
> não corresponde ao trabalho depositado.

### Sobre o sobrenome

A entrada bibliográfica do trabalho usa `OLIVEIRA, Pedro Henrique Almeida Prado
de`. "Prado de Oliveira" pode ser tratado como sobrenome composto por algumas
bibliotecas. Se o sistema oferecer validação, seguir o que ele indicar; na
dúvida, `Oliveira` é a forma consistente com a entrada usada no `CITATION.cff`
e na folha de rosto.

---

## Depois de gerar

### Variante USPSC (`paper-uspsc.tex`) — caminho oficial

Salvar o PDF devolvido como `docs/thesis/uspsc/fichacatalografica.pdf` e, em
`paper-uspsc.tex`, trocar o bloco `\begin{fichacatalografica}...\end{...}` por:

```latex
\includepdf{uspsc/fichacatalografica.pdf}
```

O pacote USPSC prevê exatamente esse fluxo (o modelo original usa
`\includepdf{USPSC-TA-PreTextual/USPSC-fichacatalografica.pdf}`).

### Variante `abntex2` (`paper.tex`)

Se optar por manter as duas variantes vivas, colar o **texto** devolvido dentro
do ambiente `fichacatalografica` já existente, substituindo o bloco de aviso
`[FICHA CATALOGRÁFICA A GERAR]`, sem reformatar.

### Conferir

```bash
cd docs/thesis && pdflatex -interaction=nonstopmode paper-uspsc.tex && pdflatex -interaction=nonstopmode paper-uspsc.tex
```

A ficha deve sair no **verso da folha de rosto** (p. 4), e a compilação deve
seguir com 0 erros e 0 citações/referências indefinidas.
