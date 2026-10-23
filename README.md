# site-security-audit

Skill do Claude Code que faz uma auditoria de segurança **não-invasiva** de sites e apps antes do lançamento:
análise estática do código (SQL injection, segredos, XSS, `.env` no git, Supabase RLS, Firebase rules, Express/Django/Flask/FastAPI/Laravel, Next.js) e requisições HTTP normais contra o site publicado (headers, TLS, cookies, CORS, caminhos expostos).

## Instalação

Copie esta pasta para `~/.claude/skills/site-security-audit/`.

## Uso

```bash
python scripts/audit.py --path <projeto> [--url https://seu-site.com] [--api-path /api/x] [--format md|json] [--fail-on alto|medio|baixo]
```

Rode `--url` apenas contra sites que são seus. Veja `SKILL.md` para o detalhe de cada check e o fluxo recomendado.
