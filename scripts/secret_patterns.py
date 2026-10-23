"""
Padrões de segredo compartilhados entre a varredura de código-fonte e a de bundle.

STRONG_PATTERNS: formato próprio do provedor — baixo índice de falso positivo,
serve tanto pro código quanto pro bundle minificado.
GENERIC_PATTERNS: heurística "password = '...'" — só pro código-fonte (no bundle
minificado gera ruído demais).
"""
import base64
import json
import re

STRONG_PATTERNS = [
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), "possível chave da API Anthropic"),
    (re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}"), "possível chave de API (padrão OpenAI)"),
    (re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}"), "possível chave secreta Stripe (live)"),
    (re.compile(r"\bwhsec_[A-Za-z0-9]{16,}"), "possível webhook secret Stripe"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "possível AWS Access Key ID"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "possível chave de API do Google"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}"), "possível token do GitHub"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"), "possível token do Slack"),
    (re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"), "chave privada PEM"),
    (re.compile(r"postgres(?:ql)?://[^:\s/]+:[^@\s]+@"), "connection string com credenciais embutidas"),
    (re.compile(r"mongodb(?:\+srv)?://[^:\s/]+:[^@\s]+@"), "connection string com credenciais embutidas"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "JWT embutido (pode ser service_role/token de sessão)"),
]

GENERIC_PATTERNS = [
    (re.compile(r"(?i)\b(api[_-]?key|secret|password|passwd|senha|token)\b[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"),
     "possível segredo hardcoded"),
]

PLACEHOLDER_HINTS = (
    "xxx", "changeme", "change-me", "your_", "your-", "<", "example", "placeholder",
    "process.env", "env.", "todo", "dummy", "sample", "test", "lorem", "****", "...",
)


def looks_like_placeholder(value):
    low = value.lower()
    return any(h in low for h in PLACEHOLDER_HINTS)


def mask(value):
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}…{value[-2:]}"


FIREBASE_CONTEXT = re.compile(r"firebaseConfig|authDomain|firebaseapp\.com|initializeApp", re.IGNORECASE)


def jwt_classification(token):
    """
    Decodifica o payload (sem validar assinatura) pra separar o que é público por
    design do que é segredo. Retorna (severidade, descrição).
    - role anon / authenticated-only anon key do Supabase: info (feita pra ir no front)
    - role service_role: alto (acesso total, ignora RLS)
    - outros: médio, baixa certeza
    """
    try:
        payload_b64 = token.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    except Exception:  # noqa: BLE001
        return "medio", "JWT embutido (não consegui decodificar o payload)"
    role = str(payload.get("role", "")).lower()
    if role == "service_role":
        return "alto", "JWT com role=service_role (chave de serviço do Supabase — acesso total, NUNCA no front)"
    if role == "anon":
        return "info", "JWT com role=anon (chave pública anon do Supabase — esperada no front; a proteção depende de RLS ativado)"
    return "medio", f"JWT embutido (role={role or 'n/d'}) — confirme se não é um token de sessão/serviço"
