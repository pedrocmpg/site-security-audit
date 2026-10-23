"""
Roda o auditor de dependências nativo do ecossistema detectado
(npm/pnpm audit para Node, pip-audit para Python) e resume por severidade.
Não instala nada. Se a ferramenta não existir, expirar ou falhar, isso vira um
achado `info` + entrada em Cobertura — nunca uma lista vazia silenciosa,
pra não passar falsa sensação de que "não há vulnerabilidades".
"""
import json
import os
import shutil
import subprocess
import sys

from findings import Finding, report_coverage, COVERAGE, prefix_locations, tag_coverage
from check_code_patterns import find_project_dirs

NPM_SEV = {"critical": "alto", "high": "alto", "moderate": "medio", "low": "baixo", "info": "info"}


def _run(cmd, root, timeout=180):
    """Executa resolvendo o caminho real (no Windows `npm` é `npm.cmd`)."""
    exe = shutil.which(cmd[0])
    if not exe:
        return None, f"`{cmd[0]}` não encontrado no PATH"
    try:
        r = subprocess.run([exe] + cmd[1:], cwd=root, capture_output=True, text=True,
                           timeout=timeout, encoding="utf-8", errors="replace")
        return r, None
    except subprocess.TimeoutExpired:
        return None, f"`{cmd[0]}` excedeu {timeout}s"
    except OSError as e:
        return None, f"não consegui executar `{cmd[0]}`: {e}"


def _skip(name, reason):
    report_coverage(name, "pulado", reason)
    return [Finding("info", "dependencias-nao-checadas", f"{name}: {reason}. Dependências NÃO foram auditadas.", None, "alta")]


def run_npm_audit(root):
    name = "dependências (npm)"
    r, err = _run(["npm", "audit", "--json"], root)
    if err:
        return _skip(name, err)
    try:
        data = json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        return _skip(name, "saída do `npm audit` não é JSON válido")

    if data.get("error"):
        e = data["error"]
        code = e.get("code", "erro")
        hint = " (gere um package-lock.json com `npm install --package-lock-only`)" if code == "ENOLOCK" else ""
        return _skip(name, f"`npm audit` falhou: {code}{hint}")

    findings = []
    # `--omit=dev` revela o que realmente vai pra produção; o resto é só ferramenta de build/teste.
    prod_names = None
    rp, _err = _run(["npm", "audit", "--omit=dev", "--json"], root)
    if rp is not None:
        try:
            prod_names = set((json.loads(rp.stdout or "{}").get("vulnerabilities") or {}).keys())
        except json.JSONDecodeError:
            prod_names = None
    for pkg, info in (data.get("vulnerabilities") or {}).items():
        sev = NPM_SEV.get(info.get("severity", "low"), "baixo")
        dev_only = prod_names is not None and pkg not in prod_names
        if dev_only and sev in ("alto", "medio"):
            sev = "baixo"
        titles = [v.get("title") for v in info.get("via", []) if isinstance(v, dict) and v.get("title")]
        detail = f" Detalhe: {titles[0]}." if titles else ""
        fix = info.get("fixAvailable")
        if fix is True:
            fix_txt = "Rode `npm audit fix`."
        elif isinstance(fix, dict):
            fix_txt = f"Atualize para {fix.get('name')}@{fix.get('version')}" + (" (mudança breaking)." if fix.get("isSemVerMajor") else ".")
        else:
            fix_txt = "Sem correção automática — verifique o advisory."
        findings.append(Finding(
            sev, "dependencia-vulneravel",
            f"Pacote '{pkg}' ({info.get('severity')}, {'direta' if info.get('isDirect') else 'transitiva'}"
            f"{', só devDependency — não vai pra produção' if dev_only else ''}).{detail} {fix_txt}",
            "package.json", "alta",
        ))
    report_coverage(name, "ok", f"{len(findings)} pacote(s) vulnerável(is)")
    return findings


def run_pnpm_audit(root):
    name = "dependências (pnpm)"
    r, err = _run(["pnpm", "audit", "--json"], root)
    if err:
        return _skip(name, err)
    try:
        data = json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        return _skip(name, "saída do `pnpm audit` não é JSON válido")
    findings = []
    for adv in (data.get("advisories") or {}).values():
        findings.append(Finding(
            NPM_SEV.get(adv.get("severity", "low"), "baixo"), "dependencia-vulneravel",
            f"Pacote '{adv.get('module_name')}' ({adv.get('severity')}): {adv.get('title')}. "
            f"Versões corrigidas: {adv.get('patched_versions') or 'n/d'}.",
            "package.json", "alta",
        ))
    report_coverage(name, "ok", f"{len(findings)} advisory(ies)")
    return findings


def run_pip_audit(root):
    name = "dependências (pip-audit)"
    req = os.path.join(root, "requirements.txt")
    cmd = ["pip-audit", "-f", "json"] + (["-r", "requirements.txt"] if os.path.exists(req) else [])
    r, err = _run(cmd, root)
    if err:
        return _skip(name, err + " (instale com `pip install pip-audit`)")
    try:
        data = json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        return _skip(name, "saída do `pip-audit` não é JSON válido")
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    findings = []
    for pkg in deps:
        for vuln in pkg.get("vulns", []):
            fixes = ", ".join(vuln.get("fix_versions") or []) or "n/d"
            findings.append(Finding(
                # pip-audit não informa severidade (CVSS); "médio" é um default conservador.
                "medio", "dependencia-vulneravel",
                f"Pacote '{pkg.get('name')}=={pkg.get('version')}' tem {vuln.get('id')}. Versões corrigidas: {fixes}.",
                "requirements.txt", "alta",
            ))
    report_coverage(name, "ok", f"{len(findings)} vulnerabilidade(s)")
    return findings


def _scan_dir(d):
    findings = []
    has = lambda f: os.path.exists(os.path.join(d, f))
    found = False
    if has("package.json"):
        found = True
        if has("pnpm-lock.yaml"):
            findings.extend(run_pnpm_audit(d))
        elif has("yarn.lock"):
            findings.extend(_skip("dependências (yarn)", "yarn.lock detectado — rode `yarn npm audit` (Berry) ou `yarn audit` manualmente"))
        elif has("bun.lockb") or has("bun.lock"):
            findings.extend(_skip("dependências (bun)", "lockfile do bun detectado — rode `bun audit` manualmente"))
        else:
            findings.extend(run_npm_audit(d))
    if has("requirements.txt") or has("pyproject.toml") or has("Pipfile"):
        found = True
        findings.extend(run_pip_audit(d))
    return findings, found


def run(root):
    """Audita cada sub-projeto (monorepo: backend/, frontend/...), não só a raiz."""
    findings = []
    any_found = False
    for d in find_project_dirs(root):
        start = len(COVERAGE)
        f, found = _scan_dir(d)
        any_found = any_found or found
        rel = os.path.relpath(d, root)
        findings.extend(prefix_locations(f, rel))
        tag_coverage(start, rel)
    if not any_found:
        report_coverage("dependências", "pulado", "nenhum manifesto (package.json/requirements.txt/pyproject.toml) encontrado")
    return findings


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    for f in run(root):
        print(f.to_markdown())
