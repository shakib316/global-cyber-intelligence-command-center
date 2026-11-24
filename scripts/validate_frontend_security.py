#!/usr/bin/env python3
"""Regression checks for the dashboard's safe HTML/URL rendering boundary."""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "index.html").read_text(encoding="utf-8")

def fail(message):
    raise SystemExit("Frontend security regression failed: " + message)

csp_marker = '<meta http-equiv="Content-Security-Policy"'
if csp_marker not in HTML:
    fail("GitHub Pages-compatible Content Security Policy meta tag is missing")
csp = HTML.split(csp_marker, 1)[1].split(">", 1)[0]
for directive in ("default-src 'self'", "base-uri 'self'", "object-src 'none'",
                  "script-src 'self' 'unsafe-inline'", "style-src 'self' 'unsafe-inline'",
                  "connect-src 'self' https://api.github.com https://raw.githubusercontent.com",
                  "form-action 'self'"):
    if directive not in csp:
        fail("CSP is missing required directive: " + directive)

# The single-file Pages design still uses inline JS/CSS; unsafe-inline is an
# explicit compatibility trade-off, not a nonce-based strict CSP.
if '<script src="http' in HTML.lower():
    fail("Unexpected remote script dependency")
for anchor in re.findall(r'<a\b[^>]*target="_blank"[^>]*>', HTML, re.I):
    if not re.search(r'\brel=["\'][^"\']*\bnoopener\b[^"\']*["\']', anchor, re.I):
        fail("A new-tab link is missing rel=noopener")
if len(re.findall(r":root\s*\{", HTML)) != 1:
    fail("Theme variables must be consolidated into one root block")
if ":focus-visible" not in HTML:
    fail("Visible keyboard focus styles are missing")
if "prefers-reduced-motion" not in HTML:
    fail("Reduced-motion support is missing")

def extract(start, end):
    try:
        return HTML.split(start, 1)[1].split(end, 1)[0]
    except IndexError:
        fail("Could not isolate renderer helper: " + start)

esc_expr = extract("const esc=s=>", ";\nconst safeUrl=u=>")
url_expr = extract("const safeUrl=u=>", ";\nconst fmt=")
inline_md = "function inlineMd(s){" + extract("function inlineMd(s){", "\n\nfunction prepareBriefing")
markdown = "function markdown(src){" + extract("function markdown(src){", "\n\nfunction kevAction")
harness = """
const assert = require('node:assert/strict');
const esc = s => ESC_EXPR;
const safeUrl = u => URL_EXPR;
INLINE_MD
MARKDOWN
const hostile = '<img src=x onerror=alert(1)><svg onload=alert(2)>';
assert(!esc(hostile).includes('<img'));
assert(!esc(hostile).includes('<svg'));
assert(esc(hostile).includes('&lt;img'));
assert.equal(safeUrl('javascript:alert(1)'), '#');
assert.equal(safeUrl('data:text/html,<script>alert(1)</script>'), '#');
assert.equal(safeUrl('http://example.com/'), '#');
assert.equal(safeUrl('not a url'), '#');
assert.equal(safeUrl('https://example.com/path'), 'https://example.com/path');
const rawHtml = inlineMd(hostile);
assert(!rawHtml.includes('<img'));
assert(!rawHtml.includes('<svg'));
const javascriptLink = inlineMd('[click](javascript:alert(1))');
assert(!javascriptLink.includes('href='));
const validLink = inlineMd('[advisory](https://example.com/advisory)');
assert(validLink.includes('href="https://example.com/advisory"'));
assert(validLink.includes('rel="noopener"'));
const renderedHeading = markdown('## <svg onload=alert(1)>');
assert(!renderedHeading.includes('<svg'));
assert(renderedHeading.includes('&lt;svg'));
const ticks = String.fromCharCode(96).repeat(3);
const renderedCode = markdown(ticks+'html\\n</code><script>alert(1)</script>\\n'+ticks);
assert(!renderedCode.includes('<script>'));
assert(renderedCode.includes('&lt;script&gt;'));
"""
harness = harness.replace("ESC_EXPR", esc_expr).replace("URL_EXPR", url_expr)
harness = harness.replace("INLINE_MD", inline_md).replace("MARKDOWN", markdown)
result = subprocess.run(["node", "-e", harness], capture_output=True, text=True)
if result.returncode:
    fail("Node renderer/XSS regression tests failed: " + result.stderr)
print("Frontend security checks passed: CSP directives, HTTPS-only links, escaped Markdown, hostile HTML, code-fence injection, and new-tab link safety.")
