---
name: site-security-audit
description: Audita a segurança de um site/app antes de lançar — sites estáticos (headers do host, CSP/HSTS, HTTPS/TLS, conteúdo misto) e apps com back-end + banco de dados (Supabase RLS, Firebase rules, Express/Django/Flask/FastAPI/Laravel, SQL injection, sessão/cookies, mass assignment, debug ligado), segredos expostos no front e no git (.env versionado), CORS, rotas sensíveis públicas, rotas de API sem auth (Next.js), monorepos e dependências vulneráveis. Use antes de publicar ou quando pedirem para "verificar a segurança do site/backend".
---

# Site Security Audit

Auditoria de segurança **não-invasiva**: analisa código-fonte e faz requisições HTTP normais (GET/HEAD/OPTIONS) contra o site. Não envia payloads de ataque, não tenta explorar vulnerabilidades, não faz brute-force. O objetivo é achar os erros mais comuns que costumam vazar em projetos pequenos antes de eles virarem incidente.

## Quando usar

- Antes de lançar/publicar um site ou app
- Depois de mudanças grandes em autenticação, API ou formulários
- Quando o usuário pedir para "checar a segurança", "auditar antes de lançar" etc.

## Como rodar

```bash
python <pasta-da-skill>/scripts/audit.py --path <projeto> [--url https://site-publicado.com] [--api-path /api/x]
```

No Windows use `python` ou `py -3` (não `python3`). A pasta da skill é `~/.claude/skills/site-security-audit`.

| Flag | O que faz |
|---|---|
| `--path` | **Obrigatório.** Raiz do projeto (checks estáticos). |
| `--url` | Opcional. Site publicado **do próprio usuário**; liga os checks de rede. |
| `--api-path` | Opcional, repetível. Endpoint de API a incluir no teste de CORS (CORS na home raramente é o que importa). |
| `--format md\|json` | Formato do relatório (padrão `md`). |
| `--fail-on alto\|medio\|baixo` | Severidade mínima que faz o script sair com código 2 (padrão `alto`; útil em CI). |
| `--output` | Onde salvar o relatório (padrão: `<projeto>/security-audit-report.md`). |

Dica: rode o **build** do projeto antes — sem pasta `dist/build/out/.next` o check de bundle é pulado.

### Supressão de falsos positivos

- Comentário `audit-ignore` na própria linha (ou numa linha de comentário logo acima) ignora aquela linha.
- Arquivo `.auditignore` na raiz do projeto: um glob por linha (`tests/`, `src/legacy/*`, `#` comenta).

## Relatório

Markdown (ou JSON) impresso no terminal e salvo no projeto, com:

- **Resumo** por severidade (Alto / Médio / Baixo / Info);
- **Cobertura**: cada check marcado como ✅ rodou, ⏭️ pulado ou ❌ falhou, com o motivo. **"Nenhum achado" só vale para os checks que rodaram** — sempre leia a Cobertura;
- **Achados** agrupados (mesma categoria+mensagem viram uma linha com `×N` e até 8 locais), com confiança (alta/média/baixa) e sugestão de correção.

O relatório lista caminhos e linhas de possíveis segredos: não faça commit dele (adicione `security-audit-report.*` ao `.gitignore`).

## O que cada módulo verifica

1. **`check_code_patterns.py`** — varre o código (ignora `node_modules`, `dist`, `build`, `.next`, `vendor`, `*.min.js`, arquivos > 1 MB; **inclui** `.github/workflows`):
   - SQL montado por concatenação/template (inclusive multilinha), `$queryRawUnsafe`, `.execute(f"...")`
   - `eval`, `new Function`, `child_process.exec`, `os.system`, `shell=True`
   - Segredos hardcoded: formatos conhecidos (Anthropic `sk-ant-`, OpenAI, Stripe `sk_live_`/`whsec_`, AWS, Google, GitHub, Slack, chave privada PEM, JWT, connection strings) + heurística `password = "..."` (confiança baixa, ignora placeholders)
   - XSS: `dangerouslySetInnerHTML`, `innerHTML =`, `document.write`, `v-html`, `{@html}`
   - CORS `origin: '*'`/`true` com `credentials: true`; TLS desligado (`rejectUnauthorized: false`); JWT `alg: none`/`ignoreExpiration`; `Math.random` perto de token/senha; MD5/SHA1; fetch/readFile com valor direto da request; `pull_request_target`
   - Arquivos `.env*` versionados no git ou fora do `.gitignore`
   - Em arquivos de teste os achados caem para `info`.

2. **`check_nextjs.py`** (só se Next.js for detectado, em qualquer sub-projeto do monorepo) — rotas `app/**/route.*` e `pages/api/**` sem sinal de auth, webhooks sem verificação de assinatura, variáveis `NEXT_PUBLIC_*` com nome de segredo, ausência de rate limit. São heurísticas: **IDOR/autorização não são detectáveis por regex**, revise à mão.

3. **`check_frontend_bundle.py`** — varre (em cada sub-projeto) `dist`, `build`, `out`, `.next/static`, `public/build` atrás de segredos de formato conhecido (mascarados no relatório) e de source maps no build. `.next/server` é ignorado (não vai pro navegador).

4. **`check_live_site.py`** (só com `--url`) — GET/HEAD/OPTIONS e uma conexão TLS normal:
   - Headers: CSP (ausente/fraca), HSTS (ausente/curto), nosniff, clickjacking (XFO ou `frame-ancestors`), Referrer-Policy, Permissions-Policy, fingerprint de servidor
   - Cookies (`Secure`/`HttpOnly`/`SameSite`, parseando atributos) — só os da primeira resposta
   - CORS: reflexão de origin (alto se com credentials), `Origin: null`, `*` + credentials; na home e em cada `--api-path`
   - Caminhos expostos **validados por conteúdo** (`.git`, `.env*`, backups, dumps, Actuator, Swagger/OpenAPI, GraphQL…); usa um caminho aleatório como baseline pra detectar SPA com fallback e evitar falso positivo
   - Script/CSS de terceiros sem `integrity` (SRI), `<form action="http://`, phpMyAdmin/Adminer expostos, páginas de debug/stack trace (Django, Werkzeug, Laravel/Whoops, Node)
   - `/admin` acessível, listagem de diretório, `security.txt`, redirect HTTP→HTTPS, validade do certificado TLS, conteúdo misto, source maps públicos

5. **`check_dependencies.py`** — audita cada sub-projeto (monorepo: `backend/`, `frontend/`…): `npm audit` (ou `pnpm audit`) e `pip-audit`. Se a ferramenta faltar, expirar ou falhar (ex. sem lockfile), vira `info` + Cobertura "pulado": nunca é silenciado. yarn/bun: apenas avisa pra rodar manualmente.

6. **`check_stack.py`** — detecta a stack (inclusive em monorepos: `backend/`, `frontend/`, até 3 níveis) e liga só o que faz sentido:
   - **Site estático** (HTML puro, Vite/React SPA, Astro, Hugo, Jekyll, Eleventy): se existe config de headers no host (`_headers`, `netlify.toml`, `vercel.json`, `firebase.json`, `.htaccess`, `staticwebapp.config.json`) e se ela define CSP/HSTS/frame; `<form action="http://`; `<script src="http://`
   - **Supabase**: tabela criada sem `enable row level security`; policies de escrita com `true` (médio se abertas a anon, baixo se só `authenticated`)
   - **Firebase**: `firestore.rules`/`storage.rules`/`database.rules.json` com `if true`, `.read/.write: true` ou modo de teste (`request.time <`)
   - **Back-end** (Express/Fastify/Nest, Django, Flask, FastAPI, Laravel/PHP, Prisma/Mongo): cookie de sessão `secure:false`/`httpOnly:false`, secret de sessão hardcoded, `err.stack` na resposta, mass assignment (`data: req.body`), NoSQL injection, `DEBUG = True`, `ALLOWED_HOSTS=['*']`, `SECRET_KEY` hardcoded, Flask `debug=True`, FastAPI CORS `*` + credentials, `APP_DEBUG=true`, SQL interpolado em PHP, Express sem helmet

Observações de comportamento:
- **JWT no front**: o payload é decodificado — `role=anon` (chave pública do Supabase) vira `info`; `role=service_role` é `alto`. Chave `AIza…` junto de `firebaseConfig`/`authDomain` vira `info` (restrinja por domínio / App Check).
- **`.env` e git**: usa o git de verdade (`ls-files`, `check-ignore`, `log --all`), então funciona em subpasta de monorepo e acha `.env` já commitado e removido depois (continua no histórico). Sem git/repositório, cai na heurística do `.gitignore` e a Cobertura avisa.
- **TLS**: o certificado é validado antes de tudo. Autoassinado / hostname errado / cadeia incompleta / expirado são `alto` (categorias `tls-*`) e os demais checks seguem sem verificar o certificado (isso aparece na Cobertura). Também checa redirect HTTP→HTTPS (até 5 hops), versão TLS antiga e expiração < 14 dias.
- **Páginas de debug**: a resposta do caminho aleatório (baseline) e da home são inspecionadas atrás de stack trace / Werkzeug / Whoops / Django debug — sem requisições extras.
- **Dependências**: em `npm audit`, vulnerabilidades que só existem em `devDependencies` são rebaixadas para `baixo`.

## Fluxo recomendado (para o Claude)

1. Rode o script **na raiz do repositório** (monorepos são detectados sozinhos) e **leia a seção Cobertura primeiro**; se algo foi pulado, diga ao usuário e sugira como habilitar (build, `--url`, lockfile).
2. Para cada achado **alto** e **médio**, abra o arquivo/linha e confirme se é real ou falso positivo antes de reportar. Descarte os falsos positivos explicitamente (e sugira `audit-ignore`/`.auditignore`).
3. **Nunca imprima o valor de um segredo** encontrado — cite só arquivo:linha. Para segredo real: mover para variável de ambiente, rotacionar a credencial e, se já foi commitado, limpar o histórico.
4. Proponha as correções por arquivo, em ordem de severidade; só aplique mudanças se o usuário pedir.
5. Termine lembrando que o scan é heurístico e **não cobre** autorização/IDOR, lógica de negócio, nem pagamentos — esses pontos precisam de revisão manual.

## Limitações (intencionais)

Esta skill **não** faz:
- Injeção de payloads (SQLi, XSS, command injection) de verdade
- Brute-force de login/senha
- Fuzzing ou scanning de portas
- Qualquer coisa contra um domínio que não seja do próprio usuário (o script avisa, mas não consegue verificar propriedade — a responsabilidade é de quem roda)

Para teste de intrusão de verdade (confirmar que uma vulnerabilidade é explorável, não só que o padrão de código é arriscado), a recomendação é rodar o **OWASP ZAP baseline scan** contra o ambiente de staging — ferramenta de terceiros, mantida pela comunidade, feita exatamente pra isso:

```bash
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://staging.seusite.com
```

Isso fica fora do escopo desta skill de propósito.
