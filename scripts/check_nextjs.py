"""
Checks específicos de projetos Next.js (rodam só se Next.js for detectado):
- rotas de API (app/**/route.*, pages/api/**) sem nenhum sinal de autenticação
- variáveis NEXT_PUBLIC_* com nome de segredo (vão pro bundle do navegador)
- webhooks sem verificação de assinatura
- ausência de qualquer rate limit nas rotas de API

São heurísticas: não dá pra provar autorização/IDOR por regex. Os achados pedem
revisão manual e têm confiança média/baixa.
"""
import json
import os
import re
import sys

from findings import Finding, report_coverage, prefix_locations
from check_code_patterns import IGNORED_DIRS, iter_code_files, find_project_dirs

ROUTE_FILE = re.compile(r"^route\.(ts|tsx|js|jsx|mjs)$")
AUTH_HINTS = re.compile(
    r"getSession|getServerSession|\bauth\s*\(|currentUser|getUser\b|requireUser|requireAuth|verifyToken|"
    r"jwt\.verify|jwtVerify|withAuth|supabase\.auth|clerk|authorization|next-auth|getToken\b|"
    r"cookies\s*\(\s*\)|validateRequest|lucia",
    re.IGNORECASE,
)
PUBLIC_ROUTE_HINT = re.compile(r"(^|/)(auth|login|logout|signin|signup|register|health|ping|status|public|cron|webhooks?)(/|\.|$)", re.IGNORECASE)
SIGNATURE_HINTS = re.compile(r"constructEvent|verifySignature|signature|svix|hmac|timingSafeEqual|createHmac|verify\(", re.IGNORECASE)
RATE_LIMIT_HINTS = re.compile(r"ratelimit|rate-limit|rate_limit|limiter|upstash|express-rate", re.IGNORECASE)
MUTATING_METHOD = re.compile(r"export\s+(?:async\s+)?(?:function|const)\s+(POST|PUT|PATCH|DELETE)\b|req\.method\s*[!=]==?\s*[\"'](POST|PUT|PATCH|DELETE)")
PUBLIC_ENV = re.compile(r"NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD)[A-Z0-9_]*")
PUBLIC_ENV_OK = re.compile(r"PUBLISHABLE|ANON|PUBLIC_KEY")
MIDDLEWARE_FILES = ("middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js")


def is_nextjs(root):
    for name in ("next.config.js", "next.config.mjs", "next.config.cjs", "next.config.ts"):
        if os.path.exists(os.path.join(root, name)):
            return True
    try:
        with open(os.path.join(root, "package.json"), "r", encoding="utf-8") as f:
            pkg = json.load(f)
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        return "next" in deps
    except (OSError, json.JSONDecodeError):
        return False


def _read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def _api_route_files(root):
    for path in iter_code_files(root):
        rel = os.path.relpath(path, root).replace("\\", "/")
        base = os.path.basename(rel)
        in_app = re.search(r"(^|/)app/", rel) and ROUTE_FILE.match(base)
        in_pages_api = re.search(r"(^|/)pages/api/", rel)
        if in_app or in_pages_api:
            yield path, rel


def _middleware_has_auth(root):
    for name in MIDDLEWARE_FILES:
        text = _read(os.path.join(root, name))
        if text and AUTH_HINTS.search(text):
            return True
    return False


def check_routes(root):
    findings = []
    middleware_auth = _middleware_has_auth(root)
    any_rate_limit = False
    n_routes = 0

    for path, rel in _api_route_files(root):
        n_routes += 1
        text = _read(path)
        if RATE_LIMIT_HINTS.search(text):
            any_rate_limit = True

        if "webhook" in rel.lower() and not SIGNATURE_HINTS.search(text):
            findings.append(Finding(
                "medio", "webhook-sem-assinatura",
                "Rota de webhook sem verificação de assinatura visível — qualquer pessoa pode forjar eventos "
                "(ex. marcar um pagamento como aprovado).",
                rel, "media", "Verifique a assinatura do provedor (ex. stripe.webhooks.constructEvent) antes de processar.",
            ))
            continue

        if PUBLIC_ROUTE_HINT.search(rel) or AUTH_HINTS.search(text):
            continue
        mutating = bool(MUTATING_METHOD.search(text))
        if middleware_auth:
            sev, extra = "baixo", " (há middleware com auth — confirme que o matcher cobre esta rota)"
        else:
            sev, extra = ("medio" if mutating else "baixo"), ""
        findings.append(Finding(
            sev, "rota-api-sem-auth",
            "Rota de API sem nenhum sinal de checagem de autenticação/sessão" + extra +
            ". Se ela expõe dados do usuário, confirme também que filtra pelo dono (IDOR).",
            rel, "baixa", "Valide a sessão no início do handler e filtre as queries pelo id do usuário autenticado.",
        ))

    if n_routes and not any_rate_limit:
        findings.append(Finding(
            "info", "sem-rate-limit",
            f"Nenhuma das {n_routes} rotas de API menciona rate limit. Login, reset de senha e rotas caras "
            "ficam expostas a abuso/brute-force.",
            None, "baixa", "Considere Upstash Ratelimit, middleware próprio ou limite no proxy/CDN.",
        ))
    return findings, n_routes


def check_public_env(root):
    findings = []
    candidates = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fn in filenames:
            if fn.startswith(".env"):
                candidates.append(os.path.join(dirpath, fn))
    candidates.extend(iter_code_files(root))

    for path in candidates:
        rel = os.path.relpath(path, root).replace("\\", "/")
        for i, line in enumerate(_read(path).splitlines(), start=1):
            if len(line) > 2000 or "audit-ignore" in line:
                continue
            for m in PUBLIC_ENV.finditer(line):
                if PUBLIC_ENV_OK.search(m.group(0)):
                    continue
                findings.append(Finding(
                    "alto", "next-public-segredo",
                    f"Variável `{m.group(0)}` tem nome de segredo mas o prefixo NEXT_PUBLIC_ a embute no bundle "
                    "do navegador. Se o valor for sensível, remova o prefixo, use só no servidor e rotacione.",
                    f"{rel}:{i}", "media",
                ))
    return findings


def run(root):
    dirs = [d for d in find_project_dirs(root) if is_nextjs(d)]
    if not dirs:
        report_coverage("next.js", "pulado", "projeto Next.js não detectado")
        return []
    findings, total = [], 0
    for d in dirs:
        f, n_routes = check_routes(d)
        f.extend(check_public_env(d))
        total += n_routes
        findings.extend(prefix_locations(f, os.path.relpath(d, root)))
    report_coverage("next.js", "ok", f"{total} rotas de API analisadas em {len(dirs)} projeto(s)")
    return findings


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    for f in run(root):
        print(f.to_markdown())
