# Auditoria de Saúde Open Source — Sovereign Vault

**Veredito:** O repositório cumpre o essencial para credibilidade acadêmica e confiança técnica, mas carece de CITATION.cff (obrigatório para tese), de publicação no crates.io (recomendado para adoção) e de DOI/Zenodo (recomendado para citação estável do artefato).

---

## Achados por Severidade

### OBRIGATÓRIO (bloqueia credibilidade acadêmica ou confiança de segurança)

| # | Lacuna | Ação Concreta |
|---|--------|---------------|
| 1 | **CITATION.cff ausente.** A tese precisa citar o artefato de forma padronizada e machine-readable. Sem ele, o artefato não é descobrível em bases de citação de software. | Criar `CITATION.cff` na raiz com os metadados da tese (conteúdo proposto ao final deste documento). |
| 2 | **Licença do texto acadêmico não está explícita.** O README diz que o PDF "não é coberto pelo Apache-2.0", mas não declara sob qual licença o texto está. Isso gera ambiguidade para quem quiser reproduzir ou citar. | Adicionar ao README e a `docs/thesis/README.md` uma nota explícita: "O texto da tese (`docs/thesis/paper.tex` e derivados) está licenciado sob CC BY-NC-ND 4.0 (ou a licença escolhida), distinta do código Apache-2.0." |

### RECOMENDADO (fortalece confiança e adoção, mas não bloqueia a defesa)

| # | Lacuna | Ação Concreta |
|---|--------|---------------|
| 3 | **Nenhum crate publicado no crates.io.** O workspace tem metadados completos (`description`, `repository`, `license`), mas `publish = false` não está explícito, e nenhum crate está preparado para publicação (falta `readme` por crate, `keywords`, `categories`). Publicar `sv-crypto`, `sv-storage`, `sv-audit` aumentaria a superfície de revisão e confiança. | Em cada crate candidato a publicação: adicionar `readme = "../../README.md"` (ou um README específico), `keywords = ["security", "cryptography", "vault"]`, `categories = ["cryptography", "security"]`, e `publish = true` (ou remover `publish = false` se estiver herdado). Decidir quais crates são biblioteca pública vs. interno. |
| 4 | **Sem DOI ou arquivamento Zenodo.** Para a tese citar o artefato de forma estável (exigência comum em programas de pós-graduação), o código precisa de um PID. | Criar um release no Zenodo (via integração GitHub-Zenodo) para a tag `v0.1.0`, obter o DOI e adicioná-lo ao `CITATION.cff` e ao README. |
| 5 | **CHANGELOG não declara explicitamente aderência ao Keep a Changelog.** O formato está correto, mas a declaração de adesão é uma prática esperada. | Adicionar ao topo do `CHANGELOG.md`: "Este projeto adere ao [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)." (já há menção, mas pode ser mais explícito sobre versionamento semântico). |
| 6 | **CI não roda `cargo deny check licenses`.** O `deny.toml` tem uma lista de licenças permitidas, mas o CI só roda `bans` e `sources`. Licenças de dependências não são validadas automaticamente. | Adicionar ao job `security-audit` no `ci.yml`: `cargo deny check licenses` (após validar a lista atual com `cargo deny check licenses --generate` e ajustar se necessário). |

### OPCIONAL (melhoria de maturidade, baixo impacto na defesa)

| # | Lacuna | Ação Concreta |
|---|--------|---------------|
| 7 | **README não tem exemplo executável "copiar e colar" que rode em 2 minutos.** O walkthrough de 5 minutos é bom, mas um exemplo mínimo de uso da CLI ou de um crate (ex.: `sv-crypto` encrypt/decrypt) faltaria para quem quer avaliar rapidamente. | Adicionar ao README um bloco "Try it in 2 minutes" com um comando único que gera uma chave, criptografa um segredo e descriptografa (pode ser um script em `examples/quickstart.sh`). |
| 8 | **CONTRIBUTING.md não menciona tempo esperado para review de segurança.** Diz "prioritize security work", mas não dá um SLA diferenciado para vulnerabilidades reportadas via PR. | Adicionar a `CONTRIBUTING.md`: "PRs que corrigem vulnerabilidades de segurança (reportadas via canal privado) são revisados em até 48h." |
| 9 | **Falta badge de OpenSSF Scorecard ou menção a ele.** Projetos de segurança são frequentemente avaliados pelo Scorecard; não ter o badge não é um defeito, mas tê-lo ajuda na confiança. | Rodar `scorecard` localmente (`scorecard --repo=github.com/pealmeida/sovereign-vault --format=short`) e, se o score for >= 7, adicionar o badge ao README. Caso contrário, usar o relatório como checklist de melhoria. |
| 10 | **deny.toml tem exceções de advisories sem link para issue de tracking.** As justificativas para `RUSTSEC-2026-0194`, `RUSTSEC-2026-0195` e `RUSTSEC-2024-0429` são boas, mas não apontam para uma issue aberta no repositório que permita acompanhar a resolução. | Adicionar a cada entrada em `ignore` um comentário com `# Tracked in #<issue-number>` após criar as issues correspondentes no GitHub. |

---

## Avaliação Detalhada por Área

### 1. Qualidade do Conteúdo dos Arquivos Existentes

| Arquivo | Avaliação |
|---------|-----------|
| **README.md** | **Bom.** Explica o que é, para quem, como instalar, como usar, estado de maturidade (v0.1.0, early release), e deixa claro que é artefato de pesquisa. Tem tabela comparativa, mapa do repositório, e link para walkthrough completo. Falta apenas um exemplo "copiar e colar" de 2 minutos (ver opcional #7). |
| **CONTRIBUTING.md** | **Bom.** Diz como rodar testes, padrão de commit (Conventional Commits), checklist de PR, DCO, e prazos de review (5/10 dias úteis). Falta apenas SLA para PRs de segurança (ver recomendado #8). |
| **SECURITY.md** | **Bom.** Tem canal de reporte (GitHub Security Advisories), política de divulgação (90 dias), e escopo claro. Responde aos requisitos mínimos. |
| **CHANGELOG.md** | **Bom.** Segue Keep a Changelog, versão 0.1.0 coerente com o estado do projeto. As entradas são descritivas e justificadas. |

### 2. CI (`.github/workflows/ci.yml`)

**Cobre:**
- ✅ Build (`cargo check`, `cargo build --release`)
- ✅ Testes (`cargo test --workspace --all-features`)
- ✅ Clippy (`cargo clippy -- -D warnings`)
- ✅ rustfmt (`cargo fmt -- --check`)
- ✅ Supply-chain: `cargo audit` (vulnerabilidades) + `cargo deny` (bans, sources)
- ✅ MSRV (1.88)
- ✅ UI: `npm audit`, `svelte-check`, `vite build`
- ✅ Validação de gateway MCP (end-to-end)
- ✅ Multi-plataforma: Ubuntu, macOS, Windows

**Falta relevante para projeto de segurança:**
- ❌ `cargo deny check licenses` não roda no CI (apenas bans/sources). Licenças de dependências não são validadas automaticamente (ver recomendado #6).

**Veredito:** CI é robusto e acima da média para projeto early-stage. A única lacuna relevante é a validação de licenças.

### 3. Release (`.github/workflows/release.yml`)

**Pontos fortes:**
- ✅ Versionamento semântico validado (tag `vMAJOR.MINOR.PATCH` coerente com `Cargo.toml`, `package.json`, `tauri.conf.json`).
- ✅ Artefatos assinados por plataforma (GPG no Linux, Apple Notarization no macOS, Authenticode no Windows).
- ✅ Checksums SHA-256 gerados (`SHA256SUMS`).
- ✅ SBOM SPDX por plataforma.
- ✅ Attestations do GitHub (provenance + SBOM).
- ✅ Release é criado como **draft**, exigindo aprovação manual antes de publicar.
- ✅ Validação de aprovação externa (audit) e registro de decisão antes de build.

**Pontos de atenção:**
- O workflow exige que `APPROVED_RELEASE_TAG`, `EXTERNAL_AUDIT_APPROVED_TAG`, e `EXTERNAL_AUDIT_REPORT_SHA256` estejam definidos como variáveis de ambiente no repositório. Isso é um **processo**, não um defeito técnico, mas deve ser documentado em `docs/PRODUCTION_RELEASE.md` (já mencionado nas notas de release).

**Veredito:** Pipeline de release é exemplar para um projeto v0.1.0. Artefatos são assinados, atestados e auditáveis.

### 4. Cargo Workspace

**Metadados no `Cargo.toml` raiz:**
- ✅ `version`, `edition`, `rust-version`, `license`, `repository`, `homepage`, `authors`.

**Metadados por crate (ex.: `sv-core`, `sv-crypto`, `sovereign-vault-desktop`):**
- ✅ Herdam `version`, `edition`, `rust-version`, `license`, `repository`.
- ✅ Têm `description` específica.
- ❌ Falta `readme` por crate (necessário para publicação no crates.io).
- ❌ Falta `keywords` e `categories` (recomendado para descoberta no crates.io).
- ❌ Não está explícito se `publish = true` ou `false`. Por padrão, crates em workspace são publicáveis se tiverem metadados completos.

**Veredito:** Metadados estão completos para uso interno, mas incompletos para publicação no crates.io. Se a intenção é publicar alguns crates como bibliotecas reutilizáveis, é necessário adicionar `readme`, `keywords`, `categories` e decidir quais crates são públicos.

### 5. `deny.toml`

**Configurado:**
- ✅ Licenças permitidas: lista explícita (Apache-2.0, MIT, BSD, ISC, Zlib, MPL-2.0, etc.).
- ✅ Advisories: 3 exceções justificadas (`RUSTSEC-2026-0194`, `RUSTSEC-2026-0195`, `RUSTSEC-2024-0429`) com explicação de por que não há fix disponível e qual o impacto (transitivo via Tauri/GTK, não atingível em runtime por agente).
- ✅ Fontes: apenas crates.io e git index oficial (`unknown-registry = "deny"`, `unknown-git = "deny"`).
- ✅ Bans: `wildcards = "deny"`, `multiple-versions = "warn"`.

**Lacuna:**
- As exceções de advisories não apontam para issues de tracking no repositório (ver opcional #10).

**Veredito:** Configuração é madura e bem justificada. As exceções são transparentes e tecnicamente corretas.

---

## Lacunas Específicas de Projeto Acadêmico Open Source

| Lacuna | Status | Impacto na Tese |
|--------|--------|-----------------|
| **CITATION.cff ausente** | ❌ Ausente | **Alto.** Sem ele, o artefato não é citável de forma padronizada em bases de software. A tese perde um canal de validação externa. |
| **DOI / Zenodo** | ❌ Ausente | **Alto.** A tese precisa de um PID estável para citar o artefato. URLs do GitHub podem mudar; DOI é permanente. |
| **Separação de licenças (código vs. texto)** | ⚠️ Parcial | **Médio.** O README diz que o PDF não é Apache-2.0, mas não declara a licença do texto. Isso gera ambiguidade para reuso acadêmico. |

---

## Conteúdo Proposto para `CITATION.cff`

Copie o bloco abaixo para `CITATION.cff` na raiz do repositório. Substitua `<DOI-A-SER-OBTIDO>` após criar o release no Zenodo.

```cff
cff-version: 1.2.0
message: "Cite this software as follows:"

type: software
title: "Sovereign Vault"
abstract: "Local-first, human-in-the-loop secrets vault built for AI agents. Implements encrypted storage, MCP-native agent access control, human approval gates, and tamper-evident audit logging. Research artifact for a Master's thesis on data sovereignty architectures for personal AI agents."

authors:
  - family-names: "Oliveira"
    given-names: "Pedro Henrique Almeida Prado de"
    orcid: "https://orcid.org/<SEU-ORCID-AQUI>"
    affiliation: "Universidade de São Paulo (USP), Instituto de Ciências Matemáticas e de Computação (ICMC)"
    city: "São Carlos"
    country: "BR"

version: "0.1.0"
doi: "<DOI-A-SER-OBTIDO>"  # Ex.: 10.5281/zenodo.XXXXXXX
date-released: "2026-07-17"  # Data da tag v0.1.0

repository-code: "https://github.com/pealmeida/sovereign-vault"
url: "https://github.com/pealmeida/sovereign-vault"

license: "Apache-2.0"

keywords:
  - "secrets-management"
  - "ai-agents"
  - "mcp"
  - "local-first"
  - "security"
  - "privacy"
  - "rust"

thesis:
  type: "mastersthesis"
  title: "Arquitetura de Soberania de Dados para Agentes de IA Pessoais: Um Modelo Local-First Baseado em Protocolos Descentralizados"
  institution: "Universidade de São Paulo (USP), Instituto de Ciências Matemáticas e de Computação (ICMC)"
  degree: "MBA em Inteligência Artificial e Big Data"
  year: 2026

preferred-citation: |
  Oliveira, P. H. A. P. de. (2026). Arquitetura de Soberania de Dados para Agentes de IA Pessoais: Um Modelo Local-First Baseado em Protocolos Descentralizados [Master's thesis, Universidade de São Paulo]. Sovereign Vault v0.1.0. https://github.com/pealmeida/sovereign-vault
```

**Próximos passos para completar o `CITATION.cff`:**
1. Obter ORCID do autor (se ainda não tiver).
2. Criar release no Zenodo para a tag `v0.1.0` e obter o DOI.
3. Substituir `<SEU-ORCID-AQUI>` e `<DOI-A-SER-OBTIDO>` no arquivo.

---

## Resumo Executivo para Defesa Acadêmica

| Critério | Status | Comentário |
|----------|--------|------------|
| Documentação básica (README, CONTRIBUTING, SECURITY, CHANGELOG) | ✅ Completo | Todos os arquivos existem e cumprem seu papel. |
| CI robusto (build, testes, clippy, fmt, audit, multi-plataforma) | ✅ Completo | CI cobre o essencial e inclui validação de gateway MCP. |
| Release assinado e atestado | ✅ Completo | Pipeline de release é exemplar para v0.1.0. |
| Metadados de publicação (crates.io) | ⚠️ Parcial | Faltam `readme`, `keywords`, `categories` por crate. |
| Política de supply-chain (deny.toml) | ✅ Completo | Licenças, advisories e fontes bem configurados. |
| CITATION.cff | ❌ Ausente | **Criar antes da defesa.** |
| DOI / Zenodo | ❌ Ausente | **Obter antes da defesa.** |
| Licença do texto acadêmico | ⚠️ Parcial | Declarar explicitamente (ex.: CC BY-NC-ND 4.0). |

**Prioridade imediata:** Criar `CITATION.cff`, obter DOI no Zenodo, e declarar a licença do texto acadêmico. Esses três itens são pré-requisitos para citação estável e reprodutibilidade da tese.
