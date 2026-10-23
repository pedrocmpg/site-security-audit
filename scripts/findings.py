"""Estrutura compartilhada de achados e cobertura usada por todos os módulos de check."""
import fnmatch
import os

SEVERITY_ORDER = {"alto": 0, "medio": 1, "baixo": 2, "info": 3}

# Registro de cobertura: cada módulo avisa se rodou ou foi pulado (e por quê),
# pra o relatório nunca passar a impressão de "tudo limpo" quando um check não rodou.
COVERAGE = []


def report_coverage(name, status, reason=""):
    """status: "ok" | "pulado" | "falhou"."""
    COVERAGE.append({"check": name, "status": status, "reason": reason})


class Finding:
    def __init__(self, severity, category, message, location=None, confidence="media", fix=None):
        """
        severity: "alto" | "medio" | "baixo" | "info"
        category: nome curto do check (ex. "sql-injection-pattern")
        message: descrição humana do achado
        location: arquivo:linha, URL, ou None
        confidence: "alta" | "media" | "baixa" — chance de não ser falso positivo
        fix: dica curta de correção (opcional)
        """
        self.severity = severity
        self.category = category
        self.message = message
        # sempre com '/' (evita 'a\\b.js' e 'a/b.js' virarem achados diferentes)
        self.location = location.replace("\\", "/") if location and not location.startswith(("http://", "https://")) else location
        self.confidence = confidence
        self.fix = fix

    def to_markdown(self):
        loc = f" `{self.location}`" if self.location else ""
        return f"- **[{self.category}]**{loc} — {self.message}"

    def to_dict(self):
        return {
            "severity": self.severity, "category": self.category, "message": self.message,
            "location": self.location, "confidence": self.confidence, "fix": self.fix,
        }


def sort_findings(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))


def unique_findings(findings):
    """Remove achados idênticos (mesma sev+categoria+mensagem+local) — ex. sub-projeto aninhado visitado 2x."""
    seen, out = set(), []
    for f in findings:
        key = (f.severity, f.category, f.message, f.location)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def dedupe_and_group(findings, max_locations=8):
    """
    Agrupa achados com mesma severidade+categoria+mensagem. Evita que 300 linhas
    iguais inundem o relatório. Retorna lista de dicts já ordenada por severidade.
    """
    groups = {}
    for f in findings:
        key = (f.severity, f.category, f.message)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "severity": f.severity, "category": f.category, "message": f.message,
                "confidence": f.confidence, "fix": f.fix, "locations": [], "count": 0,
            }
        g["count"] += 1
        if f.location and f.location not in g["locations"]:
            g["locations"].append(f.location)
    out = list(groups.values())
    for g in out:
        g["extra"] = max(0, len(g["locations"]) - max_locations)
        g["locations"] = g["locations"][:max_locations]
    return sorted(out, key=lambda g: SEVERITY_ORDER.get(g["severity"], 99))


def load_ignore_globs(root):
    """Lê .auditignore (um glob por linha, # comenta). Casa contra o caminho relativo."""
    path = os.path.join(root, ".auditignore")
    globs = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    globs.append(line.replace("\\", "/"))
    except OSError:
        pass
    return globs


def is_ignored_path(rel_path, globs):
    rel = rel_path.replace("\\", "/")
    for g in globs:
        if fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(rel, g.rstrip("/") + "/*") or rel.startswith(g.rstrip("/") + "/"):
            return True
    return False


def filter_ignored(findings, globs):
    if not globs:
        return findings
    kept = []
    for f in findings:
        loc = (f.location or "").split(":")[0]
        if loc and not loc.startswith("http") and is_ignored_path(loc, globs):
            continue
        kept.append(f)
    return kept


def prefix_locations(findings, rel):
    """Prefixa locations relativas com a subpasta do sub-projeto (monorepo)."""
    rel = rel.replace("\\", "/")
    if rel in ("", "."):
        return findings
    for f in findings:
        if f.location and not f.location.startswith(("http://", "https://")):
            f.location = f"{rel}/{f.location}".replace("\\", "/")
    return findings


def tag_coverage(start_index, rel):
    """Anexa o nome da subpasta às entradas de cobertura criadas desde `start_index`."""
    rel = rel.replace("\\", "/")
    if rel in ("", "."):
        return
    for c in COVERAGE[start_index:]:
        c["check"] = f"{c['check']} [{rel}]"
