#!/usr/bin/env python3
import json
import sys
import textwrap
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
import re

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
README_PATH = Path("README.md")
TAG_START = "<!-- CVE-LIST:START -->"
TAG_END = "<!-- CVE-LIST:END -->"
MAX_ITEMS = 10 

def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "GitHubActions-KEV-Updater"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status} ao buscar CISA KEV")
        return json.loads(resp.read())

def parse_date_utc(d: str):
    try:
        return datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)

def build_markdown(kev: dict, max_items: int) -> str:
    vulns = kev.get("vulnerabilities", [])
    vulns.sort(key=lambda v: parse_date_utc(v.get("dateAdded", "")), reverse=True)

    agora = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
    total = min(len(vulns), max_items)

    linhas = []
    
    linhas.append("<details>")
    linhas.append(f"<summary><strong>Vulnerabilidades exploradas conhecidas da CISA</strong>  •  atualizado {agora}  •  exibindo {total} itens</summary>")
    linhas.append("")
    linhas.append("> Fonte: CISA Known Exploited Vulnerabilities")
    linhas.append("")

    for v in vulns[:max_items]:
        cve = v.get("cveID", "N/A")
        nome = v.get("vulnerabilityName", "N/A")
        fornecedor = v.get("vendorProject", "N/A")
        produto = v.get("product", "N/A")
        data_add = v.get("dateAdded", "N/A")
        desc = v.get("shortDescription", "N/A")
        acao = v.get("requiredAction", "N/A")

        bloco = textwrap.dedent(f"""
        - **{cve}** - {nome}  
          Fornecedor: {fornecedor} | Produto: {produto} | Adicionado: {data_add}  
          {desc}  
          Ação requerida: {acao}
        """).strip()

       
        bloco = bloco.replace("—", "-")
        linhas.append(bloco)
        linhas.append("")

    linhas.append("</details>")
    linhas.append("") 

    return "\n".join(linhas).rstrip() + "\n"

def replace_between_tags(texto: str, bloco_novo: str, tag_inicio: str, tag_fim: str) -> str:
    pattern = re.compile(rf"({re.escape(tag_inicio)})(.*?)(\s*{re.escape(tag_fim)})", re.DOTALL)
    if not pattern.search(texto):
        raise RuntimeError("Tags de CVE não encontradas no README")
    return pattern.sub(rf"\1\n{bloco_novo}\3", texto)

def main():
    kev = fetch_json(CISA_KEV_URL)
    md = build_markdown(kev, MAX_ITEMS)
    readme = README_PATH.read_text(encoding="utf-8")
    atualizado = replace_between_tags(readme, md, TAG_START, TAG_END)
    README_PATH.write_text(atualizado, encoding="utf-8")
    print("README atualizado com KEVs mais recentes (seção dobrável)")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Erro: {e}", file=sys.stderr)
        sys.exit(1)
