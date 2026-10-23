"""
Checks por tipo de stack — estático (host/CDN) e back-end + banco de dados.

Detecta a stack pelos arquivos do projeto e liga só o que faz sentido:
- Site estático (HTML puro, Vite/React SPA, Astro, Hugo, Jekyll, Eleventy): onde os
  headers de segurança são configurados no host (_headers, netlify.toml, vercel.json...),
  <form> em http://, script em http:// no HTML-fonte.
- BaaS / banco: Supabase (tabelas sem RLS, policies abertas), Firebase (rules abertas).
- Back-end: Express/Fastify/Nest, Django, Flask, FastAPI, Laravel/PHP — configuração
  perigosa (debug ligado, cookie de sessão fraco, CORS aberto, stack trace na resposta,
  mass assignment, NoSQL injection).

Tudo é análise estática de padrão: pode ter falso positivo, e cada achado traz
arquivo+linha. Suprima com `audit-ignore` ou `.auditignore`.
"""
import json
import os
import re
import sys

from findings import Finding, report_coverage, prefix_locations
from check_code_patterns import find_project_dirs, IGNORED_DIRS, iter_code_files, is_test_file, MAX_FILE_BYTES, MAX_LINE_CHARS

SERVER_TAGS = {"express", "fastify", "nest", "django", "flask", "fastapi", "laravel", "php"}
STATIC_GENERATORS = {"astro", "hugo", "jekyll", "eleventy"}

HEADER_CONFIG_FILES = [
    "_headers", "public/_headers", "dist/_headers", "static/_headers",
    "netlify.toml", "vercel.json", "firebase.json", ".htaccess", "public/.htaccess",
    "staticwebapp.config.json", "wrangler.toml", "wrangler.json", "nginx.conf",
]


def _read(path):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return ""
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def _exists(root, *parts):
    return os.path.exists(os.path.join(root, *parts))


def _walk(root, exts=None, names=None):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fn in filenames:
            if (exts and os.path.splitext(fn)[1] in exts) or (names and fn in names):
                yield os.path.join(dirpath, fn)


# ------------------------------------------------------------------ detecção

def _detect_one(root):
    tags = set()
    deps = {}
    try:
        with open(os.path.join(root, "package.json"), "r", encoding="utf-8") as f:
            pkg = json.load(f)
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    except (OSError, json.JSONDecodeError):
        pass

    for dep, tag in (("express", "express"), ("fastify", "fastify"), ("@nestjs/core", "nest"),
                     ("astro", "astro"), ("@supabase/supabase-js", "supabase"), ("firebase", "firebase"),
                     ("firebase-admin", "firebase"), ("@prisma/client", "prisma"), ("prisma", "prisma"),
                     ("mongoose", "mongo"), ("mongodb", "mongo")):
        if dep in deps:
            tags.add(tag)

    if _exists(root, "supabase"):
        tags.add("supabase")
    if _exists(root, "firebase.json") or _exists(root, "firestore.rules"):
        tags.add("firebase")
    if _exists(root, "prisma", "schema.prisma") or _exists(root, "schema.prisma"):
        tags.add("prisma")
    if any(_exists(root, f"astro.config.{e}") for e in ("mjs", "js", "ts")):
        tags.add("astro")
    if _exists(root, "hugo.toml") or _exists(root, "hugo.yaml") or (_exists(root, "config.toml") and _exists(root, "content")):
        tags.add("hugo")
    if _exists(root, "_config.yml") and (_exists(root, "_posts") or _exists(root, "Gemfile")):
        tags.add("jekyll")
    if any(f.startswith(".eleventy") or f.startswith("eleventy.config") for f in os.listdir(root)):
        tags.add("eleventy")

    py_text = (_read(os.path.join(root, "requirements.txt")) + _read(os.path.join(root, "pyproject.toml"))).lower()
    if _exists(root, "manage.py") or "django" in py_text:
        tags.add("django")
    if re.search(r"(^|\n)\s*flask\b|\"flask\"|'flask'", py_text):
        tags.add("flask")
    if "fastapi" in py_text:
        tags.add("fastapi")
    if _exists(root, "artisan"):
        tags.add("laravel")
    if _exists(root, "composer.json") or any(True for _ in _first(_walk(root, exts={".php"}))):
        tags.add("php")

    server = tags & SERVER_TAGS
    has_html = any(_exists(root, p) for p in ("index.html", "public/index.html", "dist/index.html", "src/index.html"))
    if (tags & STATIC_GENERATORS) or (not server and has_html):
        tags.add("static")
    return tags


def detect_stack(root):
    tags = set()
    for d in find_project_dirs(root):
        tags |= _detect_one(d)
    return tags


def _first(it):
    for x in it:
        yield x
        return


# ------------------------------------------------------------------ estático

def check_static(root):
    findings = []
    cfg_files = [p for p in HEADER_CONFIG_FILES if _exists(root, *p.split("/"))]
    cfg_text = "\n".join(_read(os.path.join(root, *p.split("/"))) for p in cfg_files).lower()

    if not cfg_files:
        findings.append(Finding(
            "info", "headers-sem-config",
            "Site estático sem arquivo de configuração de headers (_headers, netlify.toml, vercel.json, firebase.json, .htaccess...). "
            "Em hospedagem estática os headers de segurança vêm dessa config — sem ela o host manda só os padrões.",
            None, "media",
            "No Cloudflare Pages/Netlify crie `_headers` com Content-Security-Policy, Strict-Transport-Security, "
            "X-Content-Type-Options, Referrer-Policy e frame-ancestors.",
        ))
    else:
        where = ", ".join(cfg_files)
        if "content-security-policy" not in cfg_text:
            findings.append(Finding("baixo", "headers-config-sem-csp",
                f"A config do host ({where}) não define Content-Security-Policy.", cfg_files[0], "media"))
        if "strict-transport-security" not in cfg_text:
            findings.append(Finding("baixo", "headers-config-sem-hsts",
                f"A config do host ({where}) não define Strict-Transport-Security (HSTS) — a menos que a plataforma o aplique por padrão.",
                cfg_files[0], "baixa"))
        if "x-frame-options" not in cfg_text and "frame-ancestors" not in cfg_text:
            findings.append(Finding("baixo", "headers-config-sem-frame",
                f"A config do host ({where}) não impede iframe (X-Frame-Options / frame-ancestors).", cfg_files[0], "media"))

    for path in _walk(root, exts={".html"}):
        rel = os.path.relpath(path, root)
        for i, line in enumerate(_read(path).splitlines(), start=1):
            if len(line) > MAX_LINE_CHARS or "audit-ignore" in line:
                continue
            if re.search(r"<form\b[^>]*action=[\"']http://", line, re.IGNORECASE):
                findings.append(Finding("medio", "form-http", "Formulário envia dados para http:// (sem criptografia).", f"{rel}:{i}", "alta"))
            if re.search(r"<(?:script|link)\b[^>]*(?:src|href)=[\"']http://(?!localhost|127\.0\.0\.1)", line, re.IGNORECASE):
                findings.append(Finding("medio", "conteudo-misto-fonte",
                    "HTML carrega script/CSS por http:// — bloqueado como conteúdo misto em HTTPS e adulterável na rede.", f"{rel}:{i}", "alta"))
    return findings


# ------------------------------------------------------------------ BaaS / banco

CREATE_TABLE = re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:\"?public\"?\.)?\"?([a-z_][a-z0-9_]*)\"?", re.IGNORECASE)
ENABLE_RLS = re.compile(r"alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?(?:\"?public\"?\.)?\"?([a-z_][a-z0-9_]*)\"?\s+enable\s+row\s+level\s+security", re.IGNORECASE)
OPEN_POLICY = re.compile(r"create\s+policy[^;]*?for\s+(insert|update|delete|all)[^;]*?(?:using|with\s+check)\s*\(\s*true\s*\)", re.IGNORECASE | re.DOTALL)


def check_supabase(root):
    findings = []
    sql_files = [p for p in _walk(root, exts={".sql"}) if "supabase" in p.replace("\\", "/").lower() or "migration" in p.lower()]
    created, rls = {}, set()
    for path in sql_files:
        text = _read(path)
        rel = os.path.relpath(path, root)
        for m in CREATE_TABLE.finditer(text):
            created.setdefault(m.group(1).lower(), f"{rel}:{text.count(chr(10), 0, m.start()) + 1}")
        for m in ENABLE_RLS.finditer(text):
            rls.add(m.group(1).lower())
        for m in OPEN_POLICY.finditer(text):
            stmt = m.group(0).lower()
            line = f"{rel}:{text.count(chr(10), 0, m.start()) + 1}"
            if re.search(r"\bto\s+authenticated\b", stmt) and not re.search(r"\bto\s+[^;]*\b(anon|public)\b", stmt):
                findings.append(Finding("baixo", "supabase-policy-aberta-logados",
                    "Policy RLS de escrita com `true` para `authenticated`: qualquer usuário LOGADO escreve/apaga. "
                    "Ok se só o dono do sistema tem conta (cadastro público desativado); risco se qualquer um puder se cadastrar.",
                    line, "media", "Desative signups no Supabase Auth ou restrinja por `auth.uid()`/claim de admin."))
            else:
                findings.append(Finding("medio", "supabase-policy-aberta",
                    "Policy RLS com `using (true)`/`with check (true)` para escrita sem restringir a usuários logados — "
                    "qualquer um (inclusive anon, com a chave pública do front) pode escrever/apagar.",
                    line, "media", "Restrinja a `to authenticated` e a `auth.uid() = user_id`."))
    for table, loc in created.items():
        if table not in rls:
            findings.append(Finding("alto", "supabase-sem-rls",
                f"Tabela `{table}` criada sem `enable row level security` nas migrations. No Supabase a chave anon fica no front — "
                "sem RLS qualquer visitante lê/escreve a tabela pela API REST.",
                loc, "media", f"alter table public.{table} enable row level security; + policies por usuário."))
    if sql_files:
        return findings, len(created)
    return findings, 0


def check_firebase(root):
    findings = []
    for path in _walk(root, names={"firestore.rules", "storage.rules", "database.rules.json"}):
        rel = os.path.relpath(path, root)
        text = _read(path)
        for i, line in enumerate(text.splitlines(), start=1):
            if "audit-ignore" in line:
                continue
            low = line.lower()
            if re.search(r"allow\s+[a-z, ]+:\s*if\s+true", low) or re.search(r"[\"']\.(read|write)[\"']\s*:\s*true", low):
                findings.append(Finding("alto", "firebase-regras-abertas",
                    "Regra de segurança aberta para qualquer pessoa (`if true` / `.read|.write: true`) — o banco/storage fica público.",
                    f"{rel}:{i}", "alta", "Exija `request.auth != null` e cheque o dono do documento (`request.auth.uid == resource.data.uid`)."))
            elif re.search(r"if\s+request\.time\s*<", low):
                findings.append(Finding("alto", "firebase-modo-teste",
                    "Regra em 'modo de teste' (`request.time < ...`): aberta até a data limite e depois quebra o app.",
                    f"{rel}:{i}", "alta"))
    return findings


# ------------------------------------------------------------------ back-end

# (regex, severidade, categoria, mensagem, confiança, extensões válidas ou None)
BACKEND_PATTERNS = [
    (re.compile(r"\b(?:secure|httpOnly)\s*:\s*false"), "medio", "cookie-sessao-fraco",
     "Cookie/sessão com `secure:false` ou `httpOnly:false` — o cookie pode vazar em HTTP ou ser lido por JavaScript (XSS).", "media", {".js", ".ts", ".mjs", ".cjs"}),
    (re.compile(r"session\s*\(\s*\{[^}]*secret\s*:\s*[\"'][^\"']+[\"']", re.DOTALL), "alto", "session-secret-hardcoded",
     "Secret da sessão escrito no código — quem lê o repositório consegue forjar sessões.", "alta", {".js", ".ts", ".mjs", ".cjs"}),
    (re.compile(r"res\.(?:send|json|status\([^)]*\)\.(?:send|json))\s*\([^)]*\b(?:err|error|e)\.stack"), "medio", "stack-trace-na-resposta",
     "Stack trace enviado na resposta HTTP — vaza caminhos, versões e lógica interna.", "alta", {".js", ".ts", ".mjs", ".cjs"}),
    (re.compile(r"\.(?:create|update|insert|save|updateOne|insertOne|findOneAndUpdate|upsert)\w*\(\s*(?:req|request|ctx\.request)\.body\s*\)|\bdata\s*:\s*(?:req|request)\.body\b|\bdata\s*:\s*\{\s*\.\.\.\s*(?:req|request)\.body\b"),
     "medio", "mass-assignment",
     "Corpo da request passado direto ao banco — o cliente pode setar campos que não deveria (role, isAdmin, userId, e em SaaS multi-loja o id do tenant). Escolha os campos permitidos.", "baixa", {".js", ".ts", ".mjs", ".cjs"}),
    (re.compile(r"\.(?:find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|countDocuments)\(\s*(?:req|request)\.(?:body|query)\b|\$where\b"),
     "medio", "nosql-injection",
     "Filtro de banco montado direto de req.body/req.query (ou uso de `$where`) — permite injeção de operadores NoSQL ({\"$ne\": null}).", "baixa", {".js", ".ts", ".mjs", ".cjs"}),
    (re.compile(r"^\s*DEBUG\s*=\s*True\b"), "alto", "django-debug",
     "`DEBUG = True` no Django — em produção mostra stack trace, settings e variáveis na página de erro.", "media", {".py"}),
    (re.compile(r"ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']\s*\]"), "medio", "django-allowed-hosts",
     "`ALLOWED_HOSTS = ['*']` aceita qualquer Host header (host header poisoning).", "media", {".py"}),
    (re.compile(r"^\s*SECRET_KEY\s*=\s*[\"'][^\"']{8,}[\"']"), "alto", "django-secret-key",
     "SECRET_KEY do Django escrita no código — permite forjar sessões/tokens. Leia de variável de ambiente.", "media", {".py"}),
    (re.compile(r"\.run\([^)]*debug\s*=\s*True|FLASK_DEBUG\s*=\s*(?:1|True|\"1\")"), "alto", "flask-debug",
     "Flask com debug ligado — o debugger Werkzeug permite execução de código se exposto.", "media", {".py"}),
    (re.compile(r"[\"'](?:select|insert\s+into|update|delete\s+from)\b[^\"']*[\"']?\s*\.\s*\$|\"[^\"]*(?:SELECT\b[^\"]*\bFROM\b|INSERT\s+INTO|UPDATE\b[^\"]*\bSET\b|DELETE\s+FROM)[^\"]*(?:\$_(?:GET|POST|REQUEST)|\$\w+)", re.IGNORECASE),
     "alto", "php-sql-interpolado",
     "SQL em PHP montado com variável interpolada na string — SQL injection clássico. Use PDO/mysqli com prepared statements.", "media", {".php"}),
]
FASTAPI_CORS = re.compile(r"allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\][\s\S]{0,300}?allow_credentials\s*=\s*True|allow_credentials\s*=\s*True[\s\S]{0,300}?allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]")


def check_backend_code(root, tags):
    findings = []
    for path in iter_code_files(root):
        ext = os.path.splitext(path)[1]
        if ext not in {".js", ".ts", ".mjs", ".cjs", ".py", ".php"}:
            continue
        rel = os.path.relpath(path, root)
        text = _read(path)
        in_test = is_test_file(rel)
        lines = text.splitlines()

        for i, line in enumerate(lines, start=1):
            if len(line) > MAX_LINE_CHARS or "audit-ignore" in line:
                continue
            for pat, sev, cat, msg, conf, exts in BACKEND_PATTERNS:
                if cat == "session-secret-hardcoded":
                    continue  # é multilinha: tratado abaixo
                if ext in exts and pat.search(line):
                    findings.append(Finding("info" if in_test else sev, cat, msg, f"{rel}:{i}", conf))

        # padrões multilinha
        if ext in {".js", ".ts", ".mjs", ".cjs"}:
            for m in BACKEND_PATTERNS[1][0].finditer(text):  # session({ ... secret: "..." })
                ln = text.count("\n", 0, m.start()) + 1
                if "audit-ignore" in lines[ln - 1]:
                    continue
                findings.append(Finding("info" if in_test else "alto", "session-secret-hardcoded", BACKEND_PATTERNS[1][3],
                                        f"{rel}:{ln}", "alta"))
        if ext == ".py" and FASTAPI_CORS.search(text):
            findings.append(Finding("medio", "fastapi-cors-aberto",
                "CORS com `allow_origins=['*']` e `allow_credentials=True` — qualquer site pode chamar a API com os cookies do usuário.",
                rel, "media", "Liste as origens permitidas explicitamente."))
    # as linhas já cobrem o padrão de session secret só em uma linha; deduplicação cuida do resto
    return findings


def check_backend_env(root):
    findings = []
    for path in _walk(root, names={".env", ".env.production", ".env.prod"}):
        rel = os.path.relpath(path, root)
        for i, line in enumerate(_read(path).splitlines(), start=1):
            if re.match(r"\s*APP_DEBUG\s*=\s*true\b", line, re.IGNORECASE):
                prod = "prod" in os.path.basename(path)
                findings.append(Finding("alto" if prod else "medio", "laravel-debug",
                    "`APP_DEBUG=true` — o Laravel mostra stack trace e variáveis de ambiente (Ignition/Whoops) na página de erro. "
                    "Em produção deve ser false.", f"{rel}:{i}", "media" if prod else "baixa"))
    return findings


def check_helmet(root, tags):
    if not tags & {"express"}:
        return []
    try:
        with open(os.path.join(root, "package.json"), "r", encoding="utf-8") as f:
            deps = json.load(f).get("dependencies", {})
    except (OSError, json.JSONDecodeError):
        return []
    if "helmet" in deps:
        return []
    return [Finding("info", "express-sem-helmet",
        "Projeto Express sem `helmet` nas dependências — os headers de segurança padrão (CSP, HSTS, nosniff, frame) não são enviados.",
        "package.json", "media", "npm i helmet e `app.use(helmet())`.")]


# ------------------------------------------------------------------ entrada

def _run_one(d):
    tags = _detect_one(d)
    findings, notes = [], []
    if "static" in tags:
        findings += check_static(d)
        notes.append("estático")
    if "supabase" in tags:
        f, n = check_supabase(d)
        findings += f
        notes.append(f"supabase ({n} tabelas)")
    if "firebase" in tags:
        findings += check_firebase(d)
        notes.append("firebase")
    if tags & SERVER_TAGS or tags & {"mongo", "prisma"}:
        findings += check_backend_code(d, tags)
        findings += check_backend_env(d)
        findings += check_helmet(d, tags)
        notes.append("back-end: " + ", ".join(sorted(tags & (SERVER_TAGS | {"mongo", "prisma"}))))
    return tags, findings, notes


def run(root):
    findings, all_tags, notes = [], set(), []
    for d in find_project_dirs(root):
        tags, f, n = _run_one(d)
        rel = os.path.relpath(d, root)
        findings += prefix_locations(f, rel)
        all_tags |= tags
        notes += [x + (f" [{rel}]" if rel != "." else "") for x in n]
    if not all_tags:
        report_coverage("stack (estático/back-end/DB)", "pulado", "nenhuma stack reconhecida")
        return findings
    report_coverage("stack (estático/back-end/DB)", "ok",
                    "detectado: " + ", ".join(sorted(all_tags)) + " → " + "; ".join(notes or ["nada específico"]))
    return findings


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    for f in run(root):
        print(f.to_markdown())
