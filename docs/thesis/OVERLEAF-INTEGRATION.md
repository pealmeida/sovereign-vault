# Integrando `paper.tex` com o Overleaf

**Contexto.** O paper vive num monorepo (`docs/thesis/paper.tex`); o Overleaf mapeia
**um projeto ↔ uma raiz de repositório**. Toda automação (git remoto, GitHub sync e
os MCP servers) roda sobre a **Git integration do Overleaf**, que é **recurso premium**
(Overleaf Cloud pago ou Server Pro ≥ 4.0) e exige um **Git token** pessoal.

## Decisão em uma linha

- Fluxo **local → Overleaf** (você escreve/gera localmente com codex/anymodel e publica):
  **Overleaf como segundo git remoto, empurrando o subtree `docs/thesis/`.** Mais simples,
  sem dependências novas, sem servidor rodando.
- Você quer que a **IA leia/escreva no Overleaf diretamente** durante o loop de revisão:
  **Overleaf MCP server** (é git-bridge por baixo, mas expõe leitura + edição por seção).
- **Sem plano premium:** git/GitHub/MCP não funcionam → cópia manual do `.tex`, ou a
  ferramenta comunitária `overleaf_sync_with_git` (engenharia reversa da API; frágil, TOS-gray).

## Comparação

| Opção | Prós | Contras | Requer premium |
|---|---|---|---|
| **Git remoto (subtree)** ⭐ | Nativo do monorepo; 1 `git push`; controle total; versionado | Reconciliação inicial de históricos não relacionados | Sim |
| **GitHub sync** | Bom se o GitHub for o hub; UI de merge no Overleaf | Mapeia repo-raiz inteiro → precisa de repo dedicado só do paper | Sim |
| **MCP server** | IA lê/edita Overleaf direto; edição por seção; auto-push | Mais peça móvel; token do Overleaf na config do MCP; ainda é git por baixo | Sim |
| **Dropbox sync** | Simples se já usa Dropbox | Indireto; sem merge; premium | Sim |
| **Upload/copiar-colar** | Zero setup | Manual, sem histórico | Não |

## Caminho recomendado — Overleaf como segundo remoto (subtree)

Mantém o paper no monorepo e publica só `docs/thesis/` na raiz do projeto Overleaf.

1. **Token + URL.** No Overleaf: *Account Settings → Git integration → gerar token*.
   No projeto: *Menu → Sync → Git* copia a URL `https://git.overleaf.com/<project-id>`.

2. **Adicionar remoto** (uma vez):
   ```bash
   git remote add overleaf https://git.overleaf.com/<project-id>
   ```
   (usuário = e-mail do Overleaf; senha = o Git token)

3. **Publicar o subtree do paper na raiz do projeto Overleaf.** O `subtree split`
   achata `docs/thesis/*` para a raiz, então `paper.tex` cai no topo (onde o Overleaf
   espera o documento principal):
   ```bash
   git subtree split --prefix=docs/thesis -b overleaf-paper
   git push overleaf overleaf-paper:master           # 1ª vez: some do estado antigo do projeto
   ```
   - Se o projeto Overleaf já tem conteúdo e você quer sobrescrever com a v2 local:
     `git push overleaf overleaf-paper:master --force` (o Overleaf vira espelho do local).
   - Para puxar edições feitas na web do Overleaf de volta:
     `git fetch overleaf && git subtree pull --prefix=docs/thesis overleaf master`

4. **Publicar revisões seguintes** (após o loop codex/anymodel regenerar `paper.tex`):
   ```bash
   git subtree split --prefix=docs/thesis -b overleaf-paper && \
   git push overleaf overleaf-paper:master --force
   ```
   (vira um alias de shell; ver "Atalho" abaixo)

> Assets: se o paper referenciar figuras, coloque-as **dentro de `docs/thesis/`** para
> que o subtree as leve à raiz do Overleaf. Hoje `paper.tex` não usa `\includegraphics`
> com arquivos externos, então não há assets a sincronizar.

### Atalho
```bash
git config alias.overleaf-push '!git subtree split --prefix=docs/thesis -b overleaf-paper && git push overleaf overleaf-paper:master --force'
# uso: git overleaf-push
```

## Se preferir o MCP server

Servidores mantidos (todos via Git integration do Overleaf, compatíveis com Claude
Desktop/Code, Cursor, Windsurf):

- **`mjyoo2/OverleafMCP`** — leitura + push de edições por seção; parsing da estrutura LaTeX.
- **`hiufungleung/overleafMCP-rw`** — CRUD completo (read/write/create/delete), auto-push.
- **`GhoshSrinjoy/Overleaf-mcp`**, **`tamirsida/overleaf_mcp`** — variantes.

Config típica (`.mcp.json` / config do cliente): `git.overleaf.com/<project-id>` + o Git
token. **Recomendação:** só adote o MCP se quiser a IA editando o Overleaf *diretamente*.
Para o fluxo atual (gerar local, publicar), `git overleaf-push` é mais simples e robusto —
o MCP é git por baixo, com uma peça a mais e o token exposto na config.

## Riscos / notas

- O Git token dá acesso de escrita ao projeto — trate como segredo (fora do repo; 0600
  ou keyring). Combina, aliás, com o próprio tema do Sovereign Vault.
- `--force` sobrescreve o estado do Overleaf: só use quando o local for a fonte da verdade.
  Se houver coautores editando na web, prefira o `subtree pull` antes de empurrar.
- Compilação continua no Overleaf (abntex2 já está lá) — resolve o único item em aberto
  (não havia toolchain TeX local).

## Fontes
- Overleaf — Git integration: https://www.overleaf.com/learn/how-to/Git_integration
- Overleaf — Git + GitHub sync: https://www.overleaf.com/learn/how-to/Git_Integration_and_GitHub_Synchronization
- MCP: https://github.com/mjyoo2/overleafmcp · https://github.com/hiufungleung/overleafMCP-rw
