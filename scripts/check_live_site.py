"""
Checks contra o site já publicado. Só faz requisições HTTP normais
(GET/HEAD/OPTIONS) e uma conexão TLS comum pra ler o certificado — nenhum
payload de ataque, nenhuma tentativa de bypass. Só stdlib, nada pra instalar.

Rode apenas contra sites que são seus.
"""
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

from findings import Finding, report_coverage

USER_AGENT = "site-security-audit/2.0 (+auditoria nao-invasiva do proprio dono)"
PATH_DELAY = 0.2  # segundos entre requisições de caminhos, pra não parecer scan agressivo
TEST_ORIGIN = "https://origem-de-teste-nao-relacionada.example"


class Resp:
    def __init__(self, status=None, headers=None, body=b"", final_url=None, error=None):
        self.status = status
        self.headers = headers if headers is not None else {}
        self.body = body
        self.final_url = final_url
        self.error = error

    def header(self, name, default=None):
        h = self.headers
        if hasattr(h, "get"):
            v = h.get(name)
            if v is None:
                for k in h.keys():
                    if k.lower() == name.lower():
                        return h[k]
            return v if v is not None else default
        return default

    def header_all(self, name):
        if hasattr(self.headers, "get_all"):
            return self.headers.get_all(name) or []
        v = self.header(name)
        return [v] if v else []


# Quando o certificado não valida, o TLS é reportado à parte (check_tls) e os demais checks
# seguem com um contexto sem verificação — senão o pior caso viraria só "conectividade".
_SSL_CTX = None


def _unverified_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def _fetch(url, method="GET", headers=None, timeout=10, limit=8192, follow=True):
    hdrs = {"User-Agent": USER_AGENT}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, method=method, headers=hdrs)
    handlers = [urllib.request.HTTPSHandler(context=_SSL_CTX)] if _SSL_CTX else []
    if not follow:
        handlers.append(_NoRedirect)
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return Resp(resp.status, resp.headers, resp.read(limit), resp.geturl())
    except urllib.error.HTTPError as e:
        try:
            body = e.read(limit)
        except Exception:
            body = b""
        return Resp(e.code, e.headers, body, url)
    except Exception as e:  # noqa: BLE001 — qualquer falha de rede vira "erro", com a causa guardada
        return Resp(None, {}, b"", url, f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------- headers

def check_headers(main):
    findings = []
    url = main.final_url
    is_https = urllib.parse.urlparse(url).scheme == "https"
    csp = main.header("content-security-policy")

    if not csp:
        findings.append(Finding("medio", "header-ausente",
            "Sem Content-Security-Policy. Ajuda a mitigar XSS limitando de onde scripts podem carregar.", url, "alta"))
    else:
        low = csp.lower()
        if re.search(r"(script-src|default-src)[^;]*\s\*(\s|;|$)", low):
            findings.append(Finding("medio", "csp-fraco", "CSP permite scripts de qualquer origem (`*`).", url, "alta"))
        if "'unsafe-inline'" in low and "'nonce-" not in low and "'strict-dynamic'" not in low:
            findings.append(Finding("baixo", "csp-fraco",
                "CSP usa 'unsafe-inline' sem nonce/strict-dynamic — reduz bastante a proteção contra XSS.", url, "media"))
        if "'unsafe-eval'" in low:
            findings.append(Finding("baixo", "csp-fraco", "CSP permite 'unsafe-eval'.", url, "media"))

    hsts = main.header("strict-transport-security")
    if not is_https:
        findings.append(Finding("alto", "sem-https",
            "O site respondeu por HTTP puro (sem TLS) — tráfego, cookies e logins ficam legíveis na rede.", url, "alta"))
    elif not hsts:
        findings.append(Finding("medio", "header-ausente",
            "Sem Strict-Transport-Security (HSTS). Sem ele, o navegador pode ser induzido a usar HTTP em vez de HTTPS.", url, "alta"))
    else:
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        if m and int(m.group(1)) < 15552000:
            findings.append(Finding("baixo", "hsts-curto",
                f"HSTS com max-age={m.group(1)}s (< 6 meses). Recomendado ≥ 31536000.", url, "media"))

    if not main.header("x-content-type-options"):
        findings.append(Finding("baixo", "header-ausente",
            "Sem X-Content-Type-Options: nosniff. Navegador pode tentar adivinhar o tipo do arquivo de forma insegura.", url, "alta"))

    has_frame_ancestors = bool(csp and "frame-ancestors" in csp.lower())
    if not main.header("x-frame-options") and not has_frame_ancestors:
        findings.append(Finding("baixo", "header-ausente",
            "Sem X-Frame-Options nem CSP frame-ancestors. Site pode ser colocado num iframe de outro domínio (clickjacking).", url, "alta"))

    if not main.header("referrer-policy"):
        findings.append(Finding("info", "header-ausente",
            "Sem Referrer-Policy definida. Pode vazar a URL completa como referrer em links externos.", url, "alta"))
    if not main.header("permissions-policy"):
        findings.append(Finding("info", "header-ausente",
            "Sem Permissions-Policy. Recomendado restringir câmera/microfone/geolocalização que o site não usa.", url, "alta"))

    server = main.header("server") or main.header("x-powered-by")
    if server and re.search(r"\d+\.\d+", server):
        findings.append(Finding("info", "fingerprint",
            f"Header revela tecnologia/versão do servidor ('{server}'), facilita achar CVE conhecida pra essa versão.", url, "alta"))
    return findings


# ---------------------------------------------------------------- cookies

def check_cookies(main):
    findings = []
    is_https = urllib.parse.urlparse(main.final_url).scheme == "https"
    for raw in main.header_all("Set-Cookie"):
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=")[0]
        attrs = {p.split("=")[0].strip().lower() for p in parts[1:]}
        missing = []
        if "secure" not in attrs and is_https:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        if missing:
            findings.append(Finding("medio", "cookie-sem-flag",
                f"Cookie '{name}' sem {', '.join(missing)}. Sem Secure/HttpOnly um cookie de sessão pode ser roubado via XSS "
                "ou enviado em HTTP puro. (Só vê cookies setados na primeira resposta — o de sessão pós-login não aparece aqui.)",
                main.final_url, "media"))
    return findings


# ---------------------------------------------------------------- CORS

def check_cors(url):
    findings = []

    def probe(origin):
        r = _fetch(url, method="OPTIONS", headers={"Origin": origin, "Access-Control-Request-Method": "GET"}, limit=256)
        if r.status is not None and not r.header("access-control-allow-origin"):
            r = _fetch(url, headers={"Origin": origin}, limit=256)
        return r

    r = probe(TEST_ORIGIN)
    if r.status is None:
        return findings
    acao = r.header("access-control-allow-origin")
    cred = (r.header("access-control-allow-credentials") or "").lower() == "true"
    if acao == TEST_ORIGIN:
        if cred:
            findings.append(Finding("alto", "cors-reflete-origin-credentials",
                "Servidor ecoa qualquer Origin E permite credentials — qualquer site de terceiros consegue fazer "
                "requisições autenticadas como o usuário e ler a resposta.", url, "alta",
                "Valide o Origin contra uma allowlist fixa."))
        else:
            findings.append(Finding("baixo", "cors-reflete-origin",
                "Servidor ecoa de volta qualquer Origin (CORS reflection) em vez de validar contra uma allowlist. "
                "Sem credentials o risco é menor, mas vira alto se a rota usar cookies.", url, "alta"))
    elif acao == "*" and cred:
        findings.append(Finding("medio", "cors-permissivo",
            "Access-Control-Allow-Origin:* junto com Allow-Credentials:true — navegadores bloqueiam essa combinação, "
            "mas indica configuração errada.", url, "alta"))

    rn = probe("null")
    if rn.status is not None and rn.header("access-control-allow-origin") == "null":
        findings.append(Finding("alto" if (rn.header("access-control-allow-credentials") or "").lower() == "true" else "medio",
            "cors-aceita-null", "Servidor aceita `Origin: null` (iframes sandbox, arquivos locais) — pode ser usado por atacante.", url, "alta"))
    return findings


# ---------------------------------------------------------------- caminhos sensíveis

ENV_LINE = re.compile(rb"(?m)^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S")


def _looks_html(b):
    return b"<html" in b[:1024].lower() or b"<!doctype html" in b[:1024].lower()


def _is_env(body, headers):
    return not _looks_html(body) and bool(ENV_LINE.search(body))


def _is_package_json(body, headers):
    if _looks_html(body):
        return False
    try:
        d = json.loads(body.decode("utf-8", "ignore"))
        return isinstance(d, dict) and ("dependencies" in d or "name" in d)
    except ValueError:
        return False


def _json_has(*keys):
    def v(body, headers):
        if _looks_html(body):
            return False
        low = body.lower()
        return any(k in low for k in keys)
    return v


# (path, severidade, mensagem, validador(body, headers) -> bool)
SENSITIVE_PATHS = [
    ("/.git/config", "alto", "Pasta .git exposta publicamente — dá pra baixar o histórico inteiro do repositório, incluindo segredos já commitados.",
     lambda b, h: b"[core]" in b),
    ("/.git/HEAD", "alto", "Pasta .git exposta publicamente (HEAD legível).", lambda b, h: b.startswith(b"ref:")),
    ("/.env", "alto", "Arquivo .env acessível publicamente — normalmente contém credenciais.", _is_env),
    ("/.env.local", "alto", "Arquivo .env.local acessível publicamente — normalmente contém credenciais.", _is_env),
    ("/.env.production", "alto", "Arquivo .env.production acessível publicamente — normalmente contém credenciais.", _is_env),
    ("/server/.env", "alto", "Arquivo .env do backend acessível publicamente.", _is_env),
    ("/.aws/credentials", "alto", "Credenciais AWS acessíveis publicamente.", lambda b, h: b"aws_access_key_id" in b.lower()),
    ("/wp-config.php.bak", "alto", "Backup de config acessível publicamente.", lambda b, h: b"DB_PASSWORD" in b or b"<?php" in b),
    ("/backup.zip", "alto", "Arquivo de backup acessível publicamente.", lambda b, h: b.startswith(b"PK\x03\x04")),
    ("/backup.sql", "alto", "Dump de banco acessível publicamente.", lambda b, h: b"INSERT INTO" in b or b"CREATE TABLE" in b),
    ("/dump.sql", "alto", "Dump de banco acessível publicamente.", lambda b, h: b"INSERT INTO" in b or b"CREATE TABLE" in b),
    ("/actuator/env", "alto", "Spring Actuator /env exposto — vaza configuração e possivelmente segredos.", _json_has(b"propertysources")),
    ("/actuator", "medio", "Spring Actuator exposto publicamente.", _json_has(b'"_links"')),
    ("/package.json", "baixo", "package.json acessível publicamente — revela dependências/versões exatas pra quem procura CVE conhecida.", _is_package_json),
    ("/.DS_Store", "info", "Arquivo de sistema do macOS vazado — revela estrutura de pastas.", lambda b, h: b.startswith(b"\x00\x00\x00\x01Bud1")),
    ("/swagger.json", "baixo", "Documentação OpenAPI/Swagger pública — mapa completo da API pra um atacante.", _json_has(b'"swagger"', b'"openapi"')),
    ("/openapi.json", "baixo", "Documentação OpenAPI pública — mapa completo da API pra um atacante.", _json_has(b'"openapi"')),
    ("/api-docs", "baixo", "Documentação de API pública (/api-docs).", _json_has(b'"openapi"', b'"swagger"')),
    ("/phpmyadmin/", "medio", "phpMyAdmin exposto publicamente — painel de banco de dados na internet.", lambda b, h: b"phpMyAdmin" in b),
    ("/adminer.php", "medio", "Adminer exposto publicamente — painel de banco de dados na internet.", lambda b, h: b"Adminer" in b),
    ("/graphql", "info", "Endpoint GraphQL respondendo a GET — confirme que introspecção/GraphiQL estão desligados em produção.",
     _json_has(b"graphiql", b"graphql")),
]

DEBUG_PATTERNS = re.compile(
    rb"Traceback \(most recent call last\)|Werkzeug Debugger|whoops-container|Whoops\\Run|Whoops! There was an error"
    rb"|You're seeing this error because you have <code>DEBUG = True|at Module\._compile|at Object\.<anonymous>"
    rb"|Fatal error: Uncaught|Stack trace:\s*(?:<[^>]*>\s*)*#0 |Symfony.Component.ErrorHandler|Illuminate.Foundation"
    rb"|<b>(?:Warning|Notice|Fatal error)</b>:\s",
)


def detect_debug(resp, url):
    """Página de erro/debug com stack trace vazando — usa respostas que já buscamos (zero requisições extras)."""
    if resp.body and DEBUG_PATTERNS.search(resp.body):
        return [Finding("alto", "debug-ativo",
            "A resposta contém stack trace / página de debug do framework — revela caminhos, versões e às vezes segredos. "
            "Desative o modo debug em produção.", url, "alta")]
    return []


DIR_LISTING_PATHS = ["/uploads/", "/backup/", "/files/", "/static/", "/assets/"]


def check_sensitive_paths(base_url, main):
    findings = []
    base = base_url.rstrip("/")

    # Baseline: caminho que certamente não existe. Se responde 200, o site é um SPA com fallback
    # (devolve index.html pra qualquer rota) e "200" sozinho não significa nada.
    baseline = _fetch(f"{base}/__audit_probe_{uuid.uuid4().hex[:8]}", limit=4096)
    spa_fallback = baseline.status == 200
    findings.extend(detect_debug(baseline, base + "/__rota-inexistente"))
    findings.extend(detect_debug(main, base_url))

    for path, sev, msg, validator in SENSITIVE_PATHS:
        r = _fetch(base + path, limit=65536)
        time.sleep(PATH_DELAY)
        if r.status == 200 and r.body and validator(r.body, r.headers):
            findings.append(Finding(sev, "caminho-exposto", f"{msg} (respondeu 200 com conteúdo compatível)", base + path, "alta"))

    # /admin: só é informativo se o site NÃO é um SPA com fallback.
    if spa_fallback:
        findings.append(Finding("info", "admin-nao-verificavel",
            "O site devolve 200 para qualquer rota (SPA com fallback), então /admin e rotas internas não podem ser "
            "checadas por HTTP — confirme manualmente que exigem login.", base_url, "alta"))
    else:
        r = _fetch(base + "/admin", limit=4096)
        time.sleep(PATH_DELAY)
        final = (r.final_url or "").lower()
        if r.status == 200 and not re.search(r"login|signin|sign-in|auth", final) and not re.search(rb"(?i)type=[\"']password", r.body):
            findings.append(Finding("medio", "admin-acessivel",
                "/admin respondeu 200 sem redirecionar para login nem mostrar formulário de senha — confirme se exige autenticação.",
                base + "/admin", "baixa"))

    # Listagem de diretório
    for p in ["/"] + DIR_LISTING_PATHS:
        r = main if p == "/" else _fetch(base + p, limit=8192)
        if p != "/":
            time.sleep(PATH_DELAY)
        if r.status == 200 and re.search(rb"(?i)<title>\s*Index of /|Directory listing for /", r.body):
            findings.append(Finding("medio", "listagem-de-diretorio",
                "Listagem de diretório habilitada — expõe nomes de arquivos que não deveriam ser públicos.", base + p, "alta"))

    # security.txt
    r = _fetch(base + "/.well-known/security.txt", limit=4096)
    if not (r.status == 200 and b"contact:" in r.body.lower()):
        findings.append(Finding("info", "sem-security-txt",
            "Sem /.well-known/security.txt — pesquisadores não têm canal oficial pra reportar vulnerabilidades.", base_url, "alta"))
    return findings


# ---------------------------------------------------------------- HTTP→HTTPS, TLS, conteúdo misto, source maps

def check_https_redirect(base_url):
    p = urllib.parse.urlparse(base_url)
    if p.scheme != "https" or not p.hostname or p.port not in (None, 443):
        return []
    start = url = f"http://{p.hostname}/"
    for _ in range(5):
        r = _fetch(url, follow=False, limit=256, timeout=6)
        if r.status is None:
            return []  # porta 80 fechada — ok
        loc = r.header("location")
        if r.status in (301, 302, 303, 307, 308) and loc:
            url = urllib.parse.urljoin(url, loc)
            if urllib.parse.urlparse(url).scheme == "https":
                return []  # redirecionou pra HTTPS
            continue
        if r.status == 200:
            break
        return []
    return [Finding("medio", "sem-redirect-https",
        "A versão HTTP do site não redireciona para HTTPS (responde 200 ou fica em HTTP após os redirects).", start, "alta",
        "Ative 'Always Use HTTPS' / redirect 301 para https no host ou CDN.")]


TLS_VERIFY_MAP = [
    ("expired", "tls-expirado", "Certificado TLS expirado."),
    ("hostname", "tls-hostname", "Certificado TLS não é válido para este domínio (hostname não confere)."),
    ("ip address mismatch", "tls-hostname", "Certificado TLS não é válido para este IP/domínio (hostname não confere)."),
    ("doesn't match", "tls-hostname", "Certificado TLS não é válido para este domínio (hostname não confere)."),
    ("self-signed", "tls-autoassinado", "Certificado TLS autoassinado — navegadores mostram alerta de segurança."),
    ("self signed", "tls-autoassinado", "Certificado TLS autoassinado — navegadores mostram alerta de segurança."),
    ("unable to get local issuer", "tls-cadeia-incompleta",
     "Cadeia de certificados não validou (intermediário ausente ou CA desconhecida)."),
]


def check_tls(base_url):
    """Retorna (achados, verificou_ok). Independente do fetch principal."""
    p = urllib.parse.urlparse(base_url)
    if p.scheme != "https" or not p.hostname:
        return [], True
    host, port = p.hostname, p.port or 443
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                version = s.version()
    except ssl.SSLCertVerificationError as e:
        msg = (e.verify_message or str(e)).lower()
        for needle, cat, text in TLS_VERIFY_MAP:
            if needle in msg:
                return [Finding("alto", cat, f"{text} ({e.verify_message})", base_url, "alta")], False
        return [Finding("alto", "tls-invalido", f"Certificado TLS não validou: {e.verify_message}.", base_url, "alta")], False
    except Exception as e:  # noqa: BLE001
        return [Finding("info", "tls-nao-checado",
            f"Não consegui negociar TLS ({type(e).__name__}: {e}).", base_url, "baixa")], True

    findings = []
    days = (datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc) - datetime.now(timezone.utc)).days
    if days < 14:
        findings.append(Finding("medio", "tls-expirando", f"Certificado TLS expira em {days} dia(s).", base_url, "alta",
            "Confirme a renovação automática (Let's Encrypt/CDN)."))
    if version in ("TLSv1", "TLSv1.1"):
        findings.append(Finding("medio", "tls-versao-antiga", f"Servidor negociou {version}; desative TLS < 1.2.", base_url, "alta"))
    return findings, True


def check_page_content(main):
    findings = []
    url = main.final_url
    body = _fetch(url, limit=524288).body  # re-lê a home com limite maior pra achar scripts
    if urllib.parse.urlparse(url).scheme == "https":
        if re.search(rb"(?i)<script[^>]+src=[\"']http://|<link[^>]+href=[\"']http://[^\"']+\.css", body):
            findings.append(Finding("medio", "conteudo-misto",
                "A página HTTPS carrega script/CSS por HTTP — o navegador bloqueia ou um atacante na rede pode adulterar.", url, "alta"))

    site_host = urllib.parse.urlparse(url).netloc
    SRI_SKIP = ("googletagmanager.com", "google-analytics.com", "fonts.googleapis.com", "fonts.gstatic.com", "gstatic.com", "googleapis.com")
    no_sri = []
    for tag in re.findall(rb"<script[^>]*>|<link[^>]*rel=[\"']?stylesheet[^>]*>", body, re.IGNORECASE):
        m = re.search(rb"(?:src|href)=[\"'](?:https?:)?//([^/\"']+)[^\"']*[\"']", tag, re.IGNORECASE)
        if not m or b"integrity=" in tag.lower():
            continue
        host = m.group(1).decode("utf-8", "ignore")
        if host == site_host or any(host.endswith(x) for x in SRI_SKIP):
            continue
        no_sri.append(host)
    if no_sri:
        findings.append(Finding("baixo", "cdn-sem-sri",
            f"{len(no_sri)} script/CSS de terceiros sem `integrity` (SRI): {', '.join(sorted(set(no_sri))[:5])}. "
            "Se o CDN for comprometido, o código malicioso roda no seu site.", url, "media",
            "Adicione integrity=\"sha384-…\" crossorigin=\"anonymous\" ou hospede o arquivo você mesmo."))
    if re.search(rb"<form[^>]*action=[\"']http://", body, re.IGNORECASE):
        findings.append(Finding("medio", "form-http",
            "Formulário envia dados para uma URL http:// (sem criptografia).", url, "alta"))

    # source maps públicos dos primeiros scripts locais
    base = url
    srcs = re.findall(rb"<script[^>]+src=[\"']([^\"']+\.js)[\"']", body, re.IGNORECASE)[:3]
    for s in srcs:
        js_url = urllib.parse.urljoin(base, s.decode("utf-8", "ignore"))
        if urllib.parse.urlparse(js_url).netloc != urllib.parse.urlparse(base).netloc:
            continue
        r = _fetch(js_url + ".map", limit=2048)
        time.sleep(PATH_DELAY)
        if r.status == 200 and r.body.lstrip().startswith(b"{") and b'"sources"' in r.body:
            findings.append(Finding("baixo", "source-map-publico",
                "Source map público — expõe o código-fonte original do front.", js_url + ".map", "alta",
                "Desative a geração de source maps (ou não os publique) no build de produção."))
            break
    return findings


# ---------------------------------------------------------------- entrada

def run(base_url, api_paths=()):
    global _SSL_CTX
    _SSL_CTX = None
    tls_findings, tls_ok = check_tls(base_url)
    if not tls_ok:
        _SSL_CTX = _unverified_context()  # segue com os demais checks mesmo com cert inválido
    main = _fetch(base_url, limit=65536)
    if main.status is None:
        report_coverage("site publicado", "falhou", f"não consegui acessar {base_url} ({main.error})")
        return tls_findings + [Finding("info", "conectividade",
            f"Não consegui acessar {base_url} ({main.error}). Checks de rede NÃO foram feitos.", base_url, "alta")]

    findings = list(tls_findings)
    findings.extend(check_headers(main))
    findings.extend(check_cookies(main))
    findings.extend(check_cors(base_url))
    for p in api_paths:
        findings.extend(check_cors(base_url.rstrip("/") + "/" + p.lstrip("/")))
    findings.extend(check_https_redirect(base_url))
    findings.extend(check_sensitive_paths(base_url, main))
    findings.extend(check_page_content(main))
    note = ("TLS inválido — demais checks feitos SEM verificar o certificado; " if not tls_ok else "") + f"{base_url}" + (f" (+{len(api_paths)} endpoint(s) de API no CORS)" if api_paths else "")
    report_coverage("site publicado", "ok", note)
    return findings


if __name__ == "__main__":
    for f in run(sys.argv[1]):
        print(f.to_markdown())
