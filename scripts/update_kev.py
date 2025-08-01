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
            raise RuntimeError(f"HTTP {resp.status} fetching CISA KEV")
        return json.loads(resp.read())

def parse_date_utc(d: str) -> datetime:
    try:
        return datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)

def build_markdown(kev: dict, max_items: int) -> str:
    vulns = kev.get("vulnerabilities", [])
    vulns.sort(key=lambda v: parse_date_utc(v.get("dateAdded", "")), reverse=True)

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    count = min(len(vulns), max_items)

    lines = []
 
    lines.append(f"<details>")
    lines.append(f"<summary><strong>CISA Known Exploited Vulnerabilities</strong>  •  updated {now_str}  •  showing {count} items</summary>")
    lines.append("")
    lines.append("> Source: CISA Known Exploited Vulnerabilities")
    lines.append("")

    for v in vulns[:max_items]:
        cve = v.get("cveID", "N/A")
        name = v.get("vulnerabilityName", "N/A")
        vendor = v.get("vendorProject", "N/A")
        product = v.get("product", "N/A")
        date_added = v.get("dateAdded", "N/A")
        desc = v.get("shortDescription", "N/A")
        required = v.get("requiredAction", "N/A")

        block = textwrap.dedent(f"""
        - **{cve}** - {name}  
          Vendor: {vendor} | Product: {product} | Added: {date_added}  
          {desc}  
          Required action: {required}
        """).strip()

        
        block = block.replace("—", "-")
        lines.append(block)
        lines.append("")

    lines.append("</details>")
    lines.append("")  

    return "\n".join(lines).rstrip() + "\n"

def replace_between_tags(text: str, new_block: str, start_tag: str, end_tag: str) -> str:
    pattern = re.compile(rf"({re.escape(start_tag)})(.*?)(\s*{re.escape(end_tag)})", re.DOTALL)
    if not pattern.search(text):
        raise RuntimeError("CVE tags not found in README")
    return pattern.sub(rf"\1\n{new_block}\3", text)

def main():
    kev = fetch_json(CISA_KEV_URL)
    md = build_markdown(kev, MAX_ITEMS)
    readme = README_PATH.read_text(encoding="utf-8")
    updated = replace_between_tags(readme, md, TAG_START, TAG_END)
    README_PATH.write_text(updated, encoding="utf-8")
    print("README updated with latest KEV entries (collapsible)")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
