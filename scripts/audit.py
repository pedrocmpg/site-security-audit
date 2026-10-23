#!/usr/bin/env python3
"""
Orquestrador da auditoria de segurança não-invasiva.

Uso:
    python audit.py --path C:\\caminho\\do\\projeto [--url https://site.com] [--api-path /api/x ...]
                    [--format md|json] [--fail-on alto|medio|baixo] [--output arquivo]

Rode a parte --url apenas contra sites que são seus.
"""
import argparse
import json
import os
import sys
import traceback
from datetime import datetime
from urllib.parse import urlparse

for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, 'reconfigure'):
        _s.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import findings as fnd
from findings import Finding, SEVERITY_ORDER, dedupe_and_group, filter_ignored, load_ignore_globs, unique_findings
import check_code_patterns
import check_nextjs
import check_stack
import check_frontend_bundle
import check_dependencies

SEVERITY_LABELS = {
    "alto": "🔴 Alto",
    "medio": "🟠 Médio",
    "baixo": "🟡 Baixo",
    "info": "⚪ Info",
}
STATUS_ICON = {"ok": "✅", "pulado": "⏭️", "falhou": "❌"}


def detect_project_type(root):
    has = lambda f: os.path.exists(os.path.join(root, f))
    found = []
    if check_nextjs.is_nextjs(root):
        found.append("Next.js")
    if any(has(f"vite.config.{e}") for e in ("js", "ts", "mjs", "mts")):
        found.append("Vite")
    if has("package.json"):
        found.append("Node/npm")
    try:
        found += sorted(check_stack.detect_stack(root))
    except Exception:  # noqa: BLE001
        pass
    for lock, label in (("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn"), ("bun.lockb", "bun"), ("bun.lock", "bun")):
        if has(lock):
            found.append(label)
    if has("requirements.txt") or has("pyproject.toml") or has("Pipfile"):
        found.append("Python")
    return found or ["não identificado"]


def safe_run(name, fn, *args, **kwargs):
    """Um módulo que quebra não derruba a auditoria: vira achado info + cobertura 'falhou'."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:  # noqa: BLE001
        tb = traceback.format_exc(limit=3).strip().splitlines()[-1]
        fnd.report_coverage(name, "falhou", f"{type(e).__name__}: {e}")
        return [Finding("info", "check-falhou", f"O check '{name}' falhou ({type(e).__name__}: {e}) e foi ignorado. {tb}", None, "alta")]


def collect(root, url, api_paths):
    fnd.COVERAGE.clear()
    all_findings = []
    all_findings += safe_run("código-fonte", check_code_patterns.run, root)
    all_findings += safe_run("next.js", check_nextjs.run, root)
    all_findings += safe_run("stack (estático/back-end/DB)", check_stack.run, root)
    all_findings += safe_run("bundle do front", check_frontend_bundle.run, root)
    all_findings += safe_run("dependências", check_dependencies.run, root)
    if url:
        import check_live_site
        all_findings += safe_run("site publicado", check_live_site.run, url, api_paths)
    else:
        fnd.report_coverage("site publicado", "pulado", "sem --url (headers, cookies, CORS e caminhos expostos não foram checados)")
    all_findings = unique_findings(filter_ignored(all_findings, load_ignore_globs(root)))
    return all_findings


def build_markdown(root, url, groups, counts):
    lines = ["# Relatório de auditoria de segurança\n"]
    lines.append(f"- Projeto: `{root}`")
    lines.append(f"- Stack detectada: {', '.join(detect_project_type(root))}")
    if url:
        lines.append(f"- URL checada: {url}")
    lines.append(f"- Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append("- ⚠️ Este arquivo lista caminhos e linhas de possíveis segredos: **não faça commit dele** (adicione `security-audit-report.*` ao `.gitignore`).")
    lines.append("")

    lines.append("## Resumo")
    for sev in ["alto", "medio", "baixo", "info"]:
        lines.append(f"- {SEVERITY_LABELS[sev]}: {counts[sev]}")
    lines.append("")

    lines.append("## Cobertura")
    for c in fnd.COVERAGE:
        reason = f" — {c['reason']}" if c["reason"] else ""
        lines.append(f"- {STATUS_ICON.get(c['status'], '•')} **{c['check']}**: {c['status']}{reason}")
    lines.append("")

    incomplete = [c for c in fnd.COVERAGE if c["status"] != "ok"]
    if not groups:
        msg = "Nenhum achado nos checks que rodaram."
        if incomplete:
            msg += f" **Atenção:** {len(incomplete)} check(s) não rodaram por completo (veja Cobertura) — ausência de achado ali não significa ausência de problema."
        else:
            msg += " Lembre que isto é um scan automatizado — não substitui revisão manual em autenticação, autorização e pagamento."
        lines.append(msg)
    else:
        lines.append("## Achados\n")
        current = None
        for g in groups:
            if g["severity"] != current:
                current = g["severity"]
                lines.append(f"\n### {SEVERITY_LABELS[current]}\n")
            locs = ", ".join(f"`{l}`" for l in g["locations"])
            if g["extra"]:
                locs += f" (+{g['extra']} outros)"
            times = f" ×{g['count']}" if g["count"] > 1 else ""
            loc_part = f" {locs}" if locs else ""
            lines.append(f"- **[{g['category']}]**{times}{loc_part} — {g['message']} _(confiança: {g['confidence']})_")
            if g["fix"]:
                lines.append(f"  - Sugestão: {g['fix']}")

    lines.append("\n---")
    lines.append(
        "Scan estático + requisições HTTP normais, sem payload de ataque. Heurístico: pode ter falso positivo e "
        "não cobre autorização/IDOR/lógica de negócio. Para confirmar exploração real, considere um OWASP ZAP baseline "
        "scan contra o ambiente de staging."
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Auditoria de segurança não-invasiva de um projeto/site.")
    parser.add_argument("--path", required=True, help="Caminho do projeto a analisar")
    parser.add_argument("--url", default=None, help="URL do SEU site publicado, pra rodar checks de rede também")
    parser.add_argument("--api-path", action="append", default=[], help="Endpoint de API a incluir no teste de CORS (repetível)")
    parser.add_argument("--format", choices=["md", "json"], default="md", help="Formato do relatório (padrão: md)")
    parser.add_argument("--fail-on", choices=["alto", "medio", "baixo"], default="alto",
                        help="Severidade mínima que faz o script sair com código 2 (padrão: alto)")
    parser.add_argument("--output", default=None, help="Arquivo de saída (padrão: <projeto>/security-audit-report.md|json)")
    args = parser.parse_args()

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"Caminho não encontrado: {root}", file=sys.stderr)
        sys.exit(1)
    if args.url:
        p = urlparse(args.url)
        if p.scheme not in ("http", "https") or not p.netloc:
            print(f"URL inválida (use http:// ou https://): {args.url}", file=sys.stderr)
            sys.exit(1)
        print(f"Aviso: checks de rede serão feitos contra {p.netloc}. Use apenas em sites que são seus.\n", file=sys.stderr)

    raw = collect(root, args.url, args.api_path)
    groups = dedupe_and_group(raw)
    counts = {"alto": 0, "medio": 0, "baixo": 0, "info": 0}
    for f in raw:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    if args.format == "json":
        report = json.dumps({
            "project": root, "url": args.url, "stack": detect_project_type(root),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "summary": counts, "coverage": fnd.COVERAGE, "findings": groups,
        }, ensure_ascii=False, indent=2)
    else:
        report = build_markdown(root, args.url, groups, counts)

    out_path = os.path.abspath(args.output) if args.output else os.path.join(root, f"security-audit-report.{args.format}")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(report)
    print(f"\n(Relatório salvo em {out_path})")

    threshold = SEVERITY_ORDER[args.fail_on]
    if any(SEVERITY_ORDER.get(f.severity, 99) <= threshold for f in raw):
        sys.exit(2)


if __name__ == "__main__":
    main()
