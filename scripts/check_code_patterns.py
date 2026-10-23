"""
Checa o código-fonte por padrões arriscados conhecidos:
- SQL montado por concatenação/template string (padrão clássico de SQL injection)
- eval / new Function / exec com entrada não controlada
- segredos hardcoded no código
- innerHTML / dangerouslySetInnerHTML / v-html com dado dinâmico (XSS)
- CORS permissivo, TLS desativado, JWT frágil, aleatoriedade fraca, SSRF/path traversal
- arquivos .env versionados ou fora do .gitignore

Isto é análise ESTÁTICA de padrão de código — nunca executa nem envia payload
contra nada. Pode ter falso positivo; cada achado inclui arquivo+linha pra
revisão humana. Suprima uma linha com o comentário `audit-ignore` (na própria
linha ou na anterior) ou um arquivo/pasta inteiro via `.auditignore`.
"""
import fnmatch
import os
import re
import shutil
import subprocess
import sys

from findings import Finding, report_coverage
from secret_patterns import (STRONG_PATTERNS, GENERIC_PATTERNS, FIREBASE_CONTEXT,
                             looks_like_placeholder, jwt_classification)

IGNORED_DIRS = {
    "node_modules", ".git", "dist", "build", ".next", "out", "coverage",
    ".venv", "venv", "__pycache__", ".turbo", ".cache", ".nuxt", ".svelte-kit",
    ".idea", ".vscode", "vendor", "bower_components", "target",
}

CODE_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py",
    ".vue", ".svelte", ".astro", ".html", ".php", ".rb", ".go", ".java", ".sql",
    ".yml", ".yaml",
}

MAX_FILE_BYTES = 1_000_000
MAX_LINE_CHARS = 2000

# --- Padrões ---

# Um "statement" SQL de verdade (não só a palavra solta): evita falso positivo
# em textos como "Select an option" + nome.
SQL_STMT = (
    r"(?:SELECT\b[^\"'`]*?\bFROM\b|INSERT\s+INTO\b|UPDATE\b[^\"'`]*?\bSET\b|DELETE\s+FROM\b"
    r"|\bWHERE\s+\w+\s*=)"
)

SQL_LINE_PATTERNS = [
    # "SELECT ... FROM x WHERE id = " + variavel
    re.compile(rf'["\'][^"\']*{SQL_STMT}[^"\']*["\']\s*\+\s*[A-Za-z_(]', re.IGNORECASE),
    # variavel + " ... SELECT ... "
    re.compile(rf'[A-Za-z_\])]\w*\s*\+\s*["\'][^"\']*{SQL_STMT}', re.IGNORECASE),
    # f-string Python
    re.compile(rf'\bf["\'][^"\']*{SQL_STMT}[^"\']*\{{[^}}]+\}}', re.IGNORECASE),
    # "...".format(
    re.compile(rf'["\'][^"\']*{SQL_STMT}[^"\']*["\']\s*\.\s*format\s*\(', re.IGNORECASE),
    # "... %s ..." % valor  (Python, formatação em vez de parâmetro)
    re.compile(rf'["\'][^"\']*{SQL_STMT}[^"\']*%s[^"\']*["\']\s*%\s*[\(\w]', re.IGNORECASE),
    # APIs "unsafe" por nome
    re.compile(r"\$(?:query|execute)RawUnsafe\s*\("),
    re.compile(r"\.execute\(\s*f[\"']", re.IGNORECASE),
]

# template literal (pode ter várias linhas): `SELECT ... ${algo} ...`
SQL_TEMPLATE = re.compile(rf"`[^`]*{SQL_STMT}[^`]*?\$\{{[^}}]+\}}[^`]*`", re.IGNORECASE)

EVAL_PATTERNS = [
    re.compile(r"\beval\s*\("),
    re.compile(r"\bnew\s+Function\s*\("),
    re.compile(r"child_process\.exec(Sync)?\s*\("),
    re.compile(r"\bos\.system\s*\("),
    re.compile(r"\bsubprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True"),
]

XSS_PATTERNS = [
    re.compile(r"dangerouslySetInnerHTML"),
    re.compile(r"\.innerHTML\s*="),
    re.compile(r"document\.write\s*\("),
    re.compile(r"\bv-html\s*="),
    re.compile(r"\{@html\b"),
]

# (regex, severidade, categoria, mensagem, confiança)
MISC_PATTERNS = [
    (re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*\]?\s*=\s*[\"']?0|rejectUnauthorized\s*:\s*false|verify\s*=\s*False"),
     "medio", "tls-desativado",
     "Validação de certificado TLS desligada — abre a porta pra man-in-the-middle. Só aceitável em dev local.", "media"),
    (re.compile(r"algorithms?\s*:\s*\[?\s*[\"']none[\"']|ignoreExpiration\s*:\s*true", re.IGNORECASE),
     "alto", "jwt-fragil",
     "JWT aceita algoritmo 'none' ou ignora expiração — tokens podem ser forjados/reutilizados.", "alta"),
    (re.compile(r"Math\.random\s*\(.*\)", re.IGNORECASE),
     "medio", "aleatoriedade-fraca",
     "Math.random() não é criptograficamente seguro. Se isto gera token/senha/código, use crypto.randomBytes / crypto.randomUUID.", "baixa"),
    (re.compile(r"createHash\(\s*[\"'](?:md5|sha1)[\"']\s*\)|hashlib\.(?:md5|sha1)\s*\(", re.IGNORECASE),
     "baixo", "hash-fraco",
     "MD5/SHA1 não servem pra senha. Use bcrypt/argon2/scrypt. (Ignore se for só checksum não-sensível.)", "baixa"),
    (re.compile(r"\bfetch\(\s*(?:req|request)\.|\baxios\.(?:get|post)\(\s*(?:req|request)\.|(?:readFile|readFileSync|createReadStream)\(\s*(?:req|request)\."),
     "medio", "ssrf-path-traversal",
     "Requisição/leitura de arquivo usando valor vindo direto da request — valide contra allowlist (SSRF / path traversal).", "baixa"),
]
# Math.random só é relevante perto de palavra de segurança, checado na linha:
RANDOM_CONTEXT = re.compile(r"token|secret|password|senha|session|sess|otp|code|codigo|api.?key|csrf|nonce|salt", re.IGNORECASE)
REACT_KEY = re.compile(r"key\s*=\s*\{")

CORS_WILDCARD_CREDENTIALS = re.compile(
    r"origin\s*:\s*(?:[\'\"]\*[\'\"]|true)[\s\S]{0,200}?credentials\s*:\s*true"
    r"|credentials\s*:\s*true[\s\S]{0,200}?origin\s*:\s*(?:[\'\"]\*[\'\"]|true)",
    re.IGNORECASE,
)
CORS_HEADER_WILDCARD = re.compile(r"Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"']\*[\"']", re.IGNORECASE)

TEST_FILE_PATTERN = re.compile(
    r"(^|[/\\])(tests?|__tests__|__mocks__|fixtures?|spec|e2e)([/\\]|$)"
    r"|\.(test|spec)\.[a-zA-Z]+$"
    r"|(^|[/\\])test[-_][^/\\]*$",
    re.IGNORECASE,
)
I18N_PATTERN = re.compile(r"(^|[/\\])(locales?|i18n|translations?|messages)([/\\]|$)", re.IGNORECASE)
PURE_WORD = re.compile(r"^[A-Za-z_.\-]+$")

ENV_NAME = re.compile(r"^\.env(\..+)?$")
ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")


PROJECT_MARKERS = ("package.json", "requirements.txt", "pyproject.toml", "Pipfile", "composer.json", "manage.py", "artisan")


def find_project_dirs(root, max_depth=3):
    """
    Pastas que são "um projeto" (têm package.json, requirements.txt etc.). Cobre monorepos
    do tipo backend/ + frontend/. Se nenhuma for achada, devolve [root].
    """
    found = []
    base_depth = root.rstrip("\\/").count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        if dirpath.count(os.sep) - base_depth >= max_depth:
            dirnames[:] = []
        if any(m in filenames for m in PROJECT_MARKERS):
            found.append(dirpath)
    return found or [root]


LOCAL_DB_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal", "postgres", "db", "mysql", "mongo", "mongodb", "redis"}


def is_local_connstring(line, match_end):
    """connection string apontando pra banco local/serviço de CI (ex. postgres://ci:ci@localhost) não é segredo real."""
    m = re.match(r"([^/:\s?\"'`]+)", line[match_end:])
    return bool(m and m.group(1).lower() in LOCAL_DB_HOSTS)


def is_test_file(rel_path):
    """
    True se o caminho está numa pasta de teste (tests/, __tests__/, fixtures/)
    ou tem nome de arquivo de teste (*.test.ts, *.spec.js). Em arquivo de
    teste, um padrão de 'código perigoso' muitas vezes é esperado — não é o
    mesmo risco que o padrão aparecer em código de produção.
    """
    return bool(TEST_FILE_PATTERN.search(rel_path.replace("\\", "/")))


def iter_code_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1]
            if ext not in CODE_EXTENSIONS:
                continue
            if fn.endswith((".min.js", ".min.mjs", ".bundle.js")):
                continue
            path = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(path) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path


def _suppressed(lines, idx):
    if "audit-ignore" in lines[idx]:
        return True
    # a linha anterior só vale se for um comentário puro (não código com comentário no fim)
    prev = lines[idx - 1].strip() if idx > 0 else ""
    return "audit-ignore" in prev and prev.startswith(("//", "#", "/*", "*", "<!--"))


def scan_file(path, root):
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return findings

    rel = os.path.relpath(path, root)
    rel_norm = rel.replace("\\", "/")
    lines = text.splitlines()
    in_test = is_test_file(rel)
    in_i18n = bool(I18N_PATTERN.search(rel_norm))
    in_workflow = rel_norm.startswith(".github/workflows/")
    test_note = " (arquivo de teste — confirme que não roda com entrada vinda de fora do projeto)"

    def sev(base):
        return "info" if in_test else base

    def note():
        return test_note if in_test else ""

    seen_sql_lines = set()
    has_firebase = bool(FIREBASE_CONTEXT.search(text))

    # template literals SQL (inclui multilinha) — roda no texto inteiro
    for m in SQL_TEMPLATE.finditer(text):
        ln = text.count("\n", 0, m.start()) + 1
        idx = ln - 1
        if idx < len(lines) and _suppressed(lines, idx):
            continue
        seen_sql_lines.add(ln)
        findings.append(Finding(
            sev("alto"), "sql-injection-pattern",
            "Query SQL parece montada por interpolação de string em vez de parametrizada. "
            "Use placeholders (?, $1, :nome) e passe os valores separadamente." + note(),
            f"{rel}:{ln}", "media",
            "Troque `${x}` por placeholders e passe os valores no segundo argumento.",
        ))

    for i, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_CHARS or _suppressed(lines, i - 1):
            continue

        if i not in seen_sql_lines:
            for pat in SQL_LINE_PATTERNS:
                if pat.search(line):
                    findings.append(Finding(
                        sev("alto"), "sql-injection-pattern",
                        "Query SQL parece montada por concatenação/interpolação de string em vez de parametrizada. "
                        "Use placeholders (?, $1, :nome) e passe os valores separadamente." + note(),
                        f"{rel}:{i}", "media",
                        "Use query parametrizada / ORM em vez de montar a string.",
                    ))
                    break

        for pat in EVAL_PATTERNS:
            if pat.search(line):
                findings.append(Finding(
                    sev("alto"), "execucao-dinamica",
                    "Execução dinâmica de código/comando (eval/Function/exec/system). "
                    "Se a entrada vier do usuário, é risco de execução arbitrária." + note(),
                    f"{rel}:{i}", "media",
                ))
                break

        for pat in XSS_PATTERNS:
            if pat.search(line):
                findings.append(Finding(
                    sev("medio"), "xss-pattern",
                    "Inserção de HTML/DOM sem passar por um sanitizador — risco de XSS se o dado vier do usuário." + note(),
                    f"{rel}:{i}", "baixa",
                    "Prefira textContent / renderização do framework; se precisar de HTML, sanitize (DOMPurify).",
                ))
                break

        for pat, base_sev, cat, msg, conf in MISC_PATTERNS:
            if cat == "aleatoriedade-fraca" and (not RANDOM_CONTEXT.search(line) or REACT_KEY.search(line)):
                continue
            if cat == "hash-fraco" and (in_test or not re.search(r"passw|senha|\bpwd\b", line, re.IGNORECASE)):
                continue
            if pat.search(line):
                findings.append(Finding(sev(base_sev), cat, msg + note(), f"{rel}:{i}", conf))

        found_secret = False
        for pat, desc in STRONG_PATTERNS:
            m = pat.search(line)
            if m:
                base_sev, conf, fix = "alto", "alta", None
                if desc.startswith("connection string") and is_local_connstring(line, m.end()):
                    base_sev, conf = "info", "media"
                    desc = "connection string de banco local/CI (host de desenvolvimento)"
                elif desc.startswith("JWT"):
                    base_sev, desc = jwt_classification(m.group(0))
                    conf = "media"
                elif desc.endswith("Google") and has_firebase:
                    base_sev, conf = "info", "media"
                    desc = "chave de API do Firebase/Google (pública por design no front)"
                    fix = "Restrinja a chave por domínio (HTTP referrer) e ative App Check; a segurança real está nas Security Rules."
                findings.append(Finding(
                    sev(base_sev), "segredo-hardcoded",
                    f"{desc}." + (" Mova para variável de ambiente e remova do histórico do git se já foi commitado." if base_sev != "info" else "") + note(),
                    f"{rel}:{i}", conf, fix,
                ))
                found_secret = True
                break
        if not found_secret and not in_i18n:
            for pat, desc in GENERIC_PATTERNS:
                m = pat.search(line)
                if not m:
                    continue
                value = m.group(2)
                if looks_like_placeholder(value) or PURE_WORD.match(value) or value.startswith(("http", "/")):
                    continue
                findings.append(Finding(
                    sev("medio"), "segredo-hardcoded",
                    f"{desc} (heurística — confirme se é um valor real). Mova para variável de ambiente." + note(),
                    f"{rel}:{i}", "baixa",
                ))
                break

        if in_workflow and "pull_request_target" in line:
            findings.append(Finding(
                "medio", "github-actions-risco",
                "Workflow usa `pull_request_target`: roda com segredos do repositório em PRs de forks. "
                "Não faça checkout/execução de código do PR nesse contexto.",
                f"{rel}:{i}", "baixa",
            ))

    if CORS_WILDCARD_CREDENTIALS.search(text):
        findings.append(Finding(
            "medio", "cors-wildcard-credentials",
            "CORS com origin '*'/true e credentials:true no mesmo bloco — combinação insegura "
            "(aceita qualquer origem com cookies); revisar.",
            rel, "media", "Use uma allowlist explícita de origens.",
        ))
    elif CORS_HEADER_WILDCARD.search(text):
        findings.append(Finding(
            "baixo", "cors-wildcard",
            "Access-Control-Allow-Origin '*' definido manualmente. Ok pra API pública sem cookies; "
            "problema se a rota usa sessão/autenticação.",
            rel, "baixa",
        ))

    return findings


def _git(root, *args, timeout=30):
    """Executa git em `root`. Retorna (returncode, stdout) ou None se não há git/timeout."""
    exe = shutil.which("git")
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "-C", root] + list(args), capture_output=True, text=True,
                           timeout=timeout, encoding="utf-8", errors="replace")
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None


def _gitignore_patterns(root):
    pats = []
    try:
        with open(os.path.join(root, ".gitignore"), "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("!"):
                    pats.append(line.lstrip("/").rstrip("/"))
    except OSError:
        pass
    return pats


def _is_template(name):
    return name.endswith(ENV_TEMPLATE_SUFFIXES)


def _env_files_on_disk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fn in filenames:
            if ENV_NAME.match(fn) and not _is_template(fn):
                yield os.path.join(dirpath, fn)


def check_env_files(root):
    """
    Usa o git de verdade (funciona em subpasta de monorepo, worktree e submódulo):
    - .env rastreado (ls-files)                      -> alto
    - .env já commitado no passado (histórico)       -> alto (segredo continua no histórico)
    - .env existe e não é ignorado (check-ignore)    -> médio
    Sem git/repositório: cai na heurística do .gitignore e avisa em Cobertura.
    """
    findings = []
    top = _git(root, "rev-parse", "--show-toplevel")
    use_git = bool(top and top[0] == 0)

    if not use_git:
        why = "git não instalado" if top is None else "pasta não é um repositório git"
        report_coverage("git (.env)", "pulado",
                        f"{why} — usei só a heurística do .gitignore; não dá pra saber se algum .env foi commitado")
        patterns = _gitignore_patterns(root)
        for path in _env_files_on_disk(root):
            fn = os.path.basename(path)
            rel = os.path.relpath(path, root).replace("\\", "/")
            if not any(fnmatch.fnmatch(fn, p) or fnmatch.fnmatch(rel, p) for p in patterns):
                findings.append(Finding(
                    "medio", "env-fora-do-gitignore",
                    "Arquivo .env não está coberto pelo .gitignore — fácil commitar por engano.",
                    rel, "baixa", "Adicione `.env*` (e `!.env.example`) ao .gitignore e `git init` para validar o histórico.",
                ))
        return findings

    tracked_now = set()
    for path in _env_files_on_disk(root):
        rel = os.path.relpath(path, root).replace("\\", "/")
        r = _git(root, "ls-files", "--error-unmatch", "--", rel)
        if r and r[0] == 0:
            tracked_now.add(rel)
            findings.append(Finding(
                "alto", "env-versionado",
                "Arquivo .env está versionado no git — qualquer segredo nele já está no histórico. "
                "Remova do índice (git rm --cached), adicione ao .gitignore e rotacione as credenciais.",
                rel, "alta",
            ))
            continue
        ig = _git(root, "check-ignore", "-q", "--", rel)
        if ig and ig[0] == 0:
            continue  # ignorado de verdade (qualquer .gitignore, global ou nested)
        findings.append(Finding(
            "medio", "env-fora-do-gitignore",
            "Arquivo .env não está ignorado pelo git — fácil commitar por engano.",
            rel, "alta", "Adicione `.env*` (e `!.env.example`) ao .gitignore.",
        ))

    hist = _git(root, "log", "--all", "--format=", "--name-only", "--relative", "--",
                ":(glob)**/.env", ":(glob)**/.env.*", timeout=60)
    n_hist = 0
    if hist and hist[0] == 0:
        seen = set()
        for line in hist[1].splitlines():
            line = line.strip().replace("\\", "/")
            if not line or line in seen or line in tracked_now or _is_template(os.path.basename(line)):
                continue
            seen.add(line)
            n_hist += 1
            findings.append(Finding(
                "alto", "env-no-historico",
                "Este .env já foi commitado em algum momento (mesmo removido depois, continua no histórico do git/GitHub). "
                "Rotacione TODAS as credenciais que estavam nele e, se o repo for público/compartilhado, limpe o histórico (git filter-repo).",
                line, "alta",
            ))
    report_coverage("git (.env)", "ok", f"repo em {top[1].strip()}; {n_hist} .env só no histórico")
    return findings


def run(root):
    all_findings = []
    n = 0
    for path in iter_code_files(root):
        n += 1
        all_findings.extend(scan_file(path, root))
    all_findings.extend(check_env_files(root))
    report_coverage("código-fonte", "ok", f"{n} arquivos analisados")
    return all_findings


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    for f in run(root):
        print(f.to_markdown())
