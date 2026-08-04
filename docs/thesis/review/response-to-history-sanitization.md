# Nota editorial — sanitização do histórico Git

Data: 2026-08-04

O histórico público foi reescrito uma única vez para remover notas privadas,
configuração local de agente, endereços pessoais de commit e caminhos absolutos
de usuário. O espelho isolado processou e preservou os 243 commits alcançáveis
pelas referências arquivadas de branches, tag e PRs, sua topologia, cronologia e
mensagens, exceto pelas substituições explícitas de identificadores privados.
Desses, 161 são alcançáveis pelas 15 branches e pela tag publicadas. Os commits
exclusivos dos antigos heads de PR permanecem no arquivo privado, pois
`refs/pull/*` é um namespace administrado pelo GitHub e depende de expurgo pelo
GitHub Support.

Os pareceres anteriores registram o identificador de proveniência vigente no
momento em que foram produzidos. Eles não foram editados retroativamente. O
commit de evidência citado nesses pareceres corresponde, após a sanitização, a
`8cea41adae5e33a3e2cb883133043aa0438c5361`, ainda alcançável pela etiqueta
anotada `thesis-evidence-preliminary`.

A equivalência foi verificada diretamente: os objetos de árvore de
`apps/thesis-eval`, `sv-mcp`, `sv-core`, `sv-storage`, `sv-privacy` e `sv-audit`
no commit de evidência são idênticos antes e depois da transformação, assim como
os blobs de `latency.csv`, `adversarial.csv` e `micro.csv` na versão da tese.
Nenhum número, resultado, qualificação ou limitação foi alterado. O registro
público consolidado está em `docs/HISTORY-SANITIZATION.md`; o mapa completo de
commits permanece no arquivo privado de custódia.
