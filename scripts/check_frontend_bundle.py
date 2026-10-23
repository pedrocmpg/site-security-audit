"""
Varre as pastas de build do front (dist/build/out/.next/static) procurando
segredos que vazaram pro código que o navegador baixa. Acontece tipicamente
quando uma variável de ambiente é exposta ao client por engano (ex. prefixo
NEXT_PUBLIC_/VITE_ num segredo) ou quando uma chave privada é colada no código.

Só usa padrões de formato conhecido (secret_patterns.STRONG_PATTERNS): o
padrão genérico "password = ..." gera ruído demais em código minificado.
Nunca imprime o segredo inteiro — só uma versão mascarada.

Não executa nada, só lê os arquivos já gerados pelo build.
"""
import os
import sys

from findings import Finding, report_coverage
from check_code_patterns import find_project_dirs
from secret_patterns import STRONG_PATTERNS, FIREBASE_CONTEXT, mask, jwt_classification

# Para .next só o que vai pro navegador: .next/static. (.next/server é código de servidor.)
BUILD_DIRS = ["dist", "build", "out", os.path.join(".next", "static"), os.path.join("public", "build")]
BUNDLE_EXTENSIONS = {".js", ".mjs", ".html", ".css", ".map"}
MAX_FILE_BYTES = 15_000_000


def find_build_dirs(root):
    found = []
    for proj in find_project_dirs(root):
        for d in BUILD_DIRS:
            candidate = os.path.join(proj, d)
            if os.path.isdir(candidate) and candidate not in found:
                found.append(candidate)
    return found


def scan_bundle(build_dir, root):
    findings = []
    sourcemaps = []
    for dirpath, dirnames, filenames in os.walk(build_dir):
        for fn in filenames:
            ext = os.path.splitext(fn)[1]
            if ext not in BUNDLE_EXTENSIONS:
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            if ext == ".map":
                sourcemaps.append(rel)
            try:
                if os.path.getsize(path) > MAX_FILE_BYTES:
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except OSError:
                continue

            seen = set()
            for pat, desc in STRONG_PATTERNS:
                for m in pat.finditer(text):
                    snippet = m.group(0)
                    if snippet in seen:
                        continue
                    seen.add(snippet)
                    sev, conf, tail = "alto", "alta", (
                        " encontrado no código enviado ao navegador. Qualquer visitante consegue ler isso no DevTools. "
                        "Remova do bundle e rotacione a credencial.")
                    d = desc  # não sobrescrever `desc`: o loop reutiliza pros próximos matches
                    if d.startswith("JWT"):
                        sev, d = jwt_classification(snippet)
                        conf = "media"
                    elif d.endswith("Google") and FIREBASE_CONTEXT.search(text):
                        sev, conf, d = "info", "media", "chave de API do Firebase/Google (pública por design)"
                    if sev == "info":
                        tail = " no bundle — esperado no front; garanta RLS/Security Rules/restrição de domínio."
                    findings.append(Finding(sev, "segredo-no-bundle", f"{d} ({mask(snippet)}){tail}", rel, conf))
    if sourcemaps:
        findings.append(Finding(
            "baixo", "source-map-no-build",
            f"{len(sourcemaps)} source map(s) (.map) no build. Se forem publicados, expõem o código-fonte original "
            "(e facilitam achar segredos/rotas).",
            sourcemaps[0], "media", "Desative productionBrowserSourceMaps / build.sourcemap no build de produção.",
        ))
    return findings


def run(root):
    build_dirs = find_build_dirs(root)
    if not build_dirs:
        report_coverage("bundle do front", "pulado", "nenhuma pasta de build encontrada (rode o build antes pra checar)")
        return []
    findings = []
    for d in build_dirs:
        findings.extend(scan_bundle(d, root))
    report_coverage("bundle do front", "ok", ", ".join(os.path.relpath(d, root) for d in build_dirs))
    return findings


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    for f in run(root):
        print(f.to_markdown())
