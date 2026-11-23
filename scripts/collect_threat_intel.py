#!/usr/bin/env python3
"""Multi-source public cyber-intelligence collector. No automated response actions."""
import datetime as dt, email.utils, html, ipaddress, json, re, sys, urllib.request, difflib
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

ROOT=Path(__file__).resolve().parents[1]
NOW=dt.datetime.now(dt.timezone.utc); IST=dt.timezone(dt.timedelta(hours=5,minutes=30)); NOW_IST=NOW.astimezone(IST); DAY=NOW_IST.date().isoformat(); DAY_UTC=NOW.date().isoformat(); STAMP=NOW.strftime("%Y-%m-%dT%H:%M:%SZ"); STAMP_IST=NOW_IST.strftime("%Y-%m-%d %H:%M:%S IST")
KEV="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CERTIN="https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST02&year="+str(NOW.year)
UA="GCI-Command-Center/2.0 (+https://github.com/shakib316/global-cyber-intelligence-command-center)"
FEEDS=[
("cisa_all","CISA All Advisories","https://www.cisa.gov/cybersecurity-advisories/all.xml","government","critical"),
("cisa_ics","CISA ICS Advisories","https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml","government","high"),
("msrc","Microsoft MSRC","https://api.msrc.microsoft.com/update-guide/rss","vendor","high"),
("aws","AWS Security Bulletins","https://aws.amazon.com/security/security-bulletins/rss/feed/","vendor","high"),
("splunk","Splunk Security Advisories","https://advisory.splunk.com/feed.xml","vendor","high"),
("uk_ncsc","UK NCSC","https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml","government","high"),
("canada_cccs","Canadian CCCS","https://www.cyber.gc.ca/api/cccs/atom/v1/get?feed=alerts_advisories&lang=en","government","medium"),
("australia_acsc","Australian ACSC","https://www.cyber.gov.au/rss/alerts","government","medium"),
("cert_eu","CERT-EU","https://cert.europa.eu/publications/security-advisories-rss","government","medium"),
("sans_isc","SANS Internet Storm Center","https://isc.sans.edu/rssfeed.xml","research","high"),
("bleepingcomputer","BleepingComputer","https://www.bleepingcomputer.com/feed/","news","medium"),
("thehackernews","The Hacker News","https://thehackernews.com/feeds/posts/default","news","medium"),
("talos","Cisco Talos","https://blog.talosintelligence.com/rss/","research","high"),
("unit42","Palo Alto Unit 42","https://unit42.paloaltonetworks.com/feed/","research","high"),
("google_ti","Google Threat Intelligence / Mandiant","https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v","research","critical"),

("cisco_psirt","Cisco PSIRT","https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml","vendor","critical"),
("fortinet_psirt","Fortinet PSIRT","https://www.fortiguard.com/rss/ir.xml","vendor","high"),
("google_security","Google Security Blog","https://security.googleblog.com/feeds/posts/default","vendor","high"),
("redhat_security","Red Hat Security Advisories","https://access.redhat.com/security/data/metrics/rhsa.rss","vendor","high"),
("rapid7","Rapid7 Research","https://www.rapid7.com/blog/rss/","research","high"),
("sophos_xops","Sophos X-Ops","https://news.sophos.com/en-us/category/threat-research/feed/","research","high"),
("crowdstrike","CrowdStrike Blog","https://www.crowdstrike.com/blog/feed/","research","high"),
("ubuntu_security","Ubuntu Security Notices","https://ubuntu.com/security/notices/rss.xml","vendor","high"),
("cloudflare_security","Cloudflare Security Blog","https://blog.cloudflare.com/tag/security/rss/","vendor","high")]

BUSINESS_FEEDS=[
("google_news_ma","Google News · Cybersecurity M&A","https://news.google.com/rss/search?q=cybersecurity+(acquisition+OR+acquires+OR+merger+OR+buyout)&hl=en-IN&gl=IN&ceid=IN:en"),
("google_news_funding","Google News · Cybersecurity funding","https://news.google.com/rss/search?q=cybersecurity+(funding+OR+investment+OR+venture+OR+IPO)&hl=en-IN&gl=IN&ceid=IN:en"),
("google_news_market","Google News · Cybersecurity market moves","https://news.google.com/rss/search?q=cybersecurity+(partnership+OR+launches+OR+appoints+OR+CEO+OR+earnings+OR+layoffs)&hl=en-IN&gl=IN&ceid=IN:en"),
("google_news_deals","Google News · Security company deals","https://news.google.com/rss/search?q=(cybersecurity+OR+security+software)+(acquires+OR+acquisition+OR+merger+OR+buys+OR+deal)&hl=en-IN&gl=IN&ceid=IN:en"),
("google_news_companies","Google News · Cybersecurity company updates","https://news.google.com/rss/search?q=(CrowdStrike+OR+Palo+Alto+Networks+OR+Fortinet+OR+Zscaler+OR+SentinelOne+OR+Cloudflare)+(results+OR+launch+OR+partnership+OR+CEO+OR+revenue)&hl=en-IN&gl=IN&ceid=IN:en"),
("google_news_india","Google News · India cybersecurity business","https://news.google.com/rss/search?q=India+cybersecurity+(investment+OR+acquisition+OR+partnership+OR+startup+OR+funding)&hl=en-IN&gl=IN&ceid=IN:en"),
("google_news_workforce","Google News · Security workforce and market","https://news.google.com/rss/search?q=cybersecurity+(layoffs+OR+hiring+OR+workforce+OR+restructuring+OR+leadership)&hl=en-IN&gl=IN&ceid=IN:en"),
("cyberscoop","CyberScoop","https://cyberscoop.com/feed/"),
("securityweek","SecurityWeek","https://www.securityweek.com/feed/"),
("darkreading","Dark Reading","https://www.darkreading.com/rss.xml"),
("therecord","The Record","https://therecord.media/feed"),
("techcrunch_security","TechCrunch Security","https://techcrunch.com/category/security/feed/")]
BUSINESS_RULES=[
("M&A",r"acquir|acquisition|merger|buyout|takeover|divest"),
("Funding & investment",r"funding|investment|venture capital|series [a-f]|\bIPO\b|raises? .*million|raises? .*billion"),
("Partnerships",r"partnership|partners with|strategic alliance|collaboration"),
("Law enforcement & operations",r"operation [A-Z]|launches? (?:a )?nationwide operation|law enforcement operation|FBI .*operation|police operation|arrests? .*cyber|takedown"),
("Cyber incidents & breaches",r"cyberattack|data breach|breached|ransomware attack|security incident|unauthorized access|unauthorised access|systems? restored after"),
("Products & launches",r"launch|unveil|introduc|general availability|releases? .*platform"),
("Leadership",r"appoint|names? .*ceo|steps down|resign|leadership|chief .* officer"),
("Financial results",r"quarterly results|revenue|earnings|financial results|forecast"),
("Workforce & restructuring",r"layoff|job cuts|restructur|workforce|redundanc"),
("Regulation & policy",r"regulat|antitrust|sanction|policy change")]
def business_category(s):
    for name,pattern in BUSINESS_RULES:
        if re.search(pattern,s,re.I):return name
    return "Company & market updates"
def deal_status(s):
    text=str(s or "")
    if not re.search(r"acquir|acquisition|merger|buyout|takeover|divest",text,re.I):return "Not applicable"
    if re.search(r"terminated|called off|abandoned|withdrawn",text,re.I):return "Terminated"
    if re.search(r"completed|closed the acquisition|has acquired|finalized|finalised",text,re.I):return "Completed"
    if re.search(r"rumou?red|reportedly|in talks|talks? (?:to acquire|over acquisition|reported)|reported .*acquisition talks|potential (?:acquisition|merger|buyout)|exploring (?:a sale|an acquisition)|considering acquisition|sources say",text,re.I):return "Rumoured"
    if re.search(r"definitive agreement|agreed to acquire|signed .*agreement|signed a deal",text,re.I):return "Signed"
    if re.search(r"announces? (?:plans? to )?acquir|announced .*acquisition|to acquire|acquisition announced|merger announced",text,re.I):return "Announced"
    return "Rumoured" if re.search(r"report|potential|explor|consider|talk",text,re.I) else "Announced"

def is_stock_market_noise(s):
    """Drop price-target/stock-move stories that do not report a company event."""
    stock_signal = re.search(r"\b(?:stock|stocks|share price|shares|price target|fair value|analyst rating|trading session|market valuation)\b", s, re.I)
    material_event = re.search(r"acquir|merger|buyout|funding|investment|partnership|launch|appoint|resign|layoff|restruct|quarterly results|revenue|earnings|financial results|forecast|regulat|antitrust|sanction", s, re.I)
    return bool(stock_signal and not material_event and business_category(s) == "Company & market updates")

CVE=re.compile(r"\bCVE-\d{4}-\d{4,}\b",re.I)
def extract_cves(*values):
    """Extract CVE IDs from every available evidence field; CVE ID length is variable."""
    return sorted({m.upper() for value in values if value for m in CVE.findall(str(value))})

IOCCTX=re.compile(r"(?i)\b(iocs?|indicators? of compromise|c2|command[- ]and[- ]control|callback|malicious (?:ip|domain|url|hash)|payload hash|sha(?:256|1|512)|ip address|domain names?)\b")
IP=re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
DOMAIN=re.compile(r"(?i)(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|biz|xyz|top|ru|cn|uk|in|io|dev|app|cloud|site|online|live|me|co|gov|edu|eu|de|fr|br|au|ca|jp|tech|pro|work|shop|store|click|link|pw|cc|to|ws)(?![\w.-])")
HASH=re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")

def fetch(url):
    req=urllib.request.Request(url,headers={"User-Agent":UA,"Accept":"application/rss+xml, application/atom+xml, application/xml, text/xml, text/html, application/json, */*"})
    with urllib.request.urlopen(req,timeout=25) as r:
        if r.status!=200: raise RuntimeError("HTTP "+str(r.status))
        return r.read()
def lname(t): return t.rsplit("}",1)[-1].lower()
def child(n,names):
    for c in list(n):
        if lname(c.tag) in names:return "".join(c.itertext()).strip()
    return ""
def parse_date(s):
    if not s:return None
    try:
        d=dt.datetime.fromisoformat(s.strip().replace("Z","+00:00"))
        return d.replace(tzinfo=dt.timezone.utc) if d.tzinfo is None else d.astimezone(dt.timezone.utc)
    except ValueError:
        try:
            d=email.utils.parsedate_to_datetime(s)
            return d.replace(tzinfo=dt.timezone.utc) if d.tzinfo is None else d.astimezone(dt.timezone.utc)
        except Exception:return None
def parse_feed(raw,f):
    root=ET.fromstring(raw);out=[]
    for n in root.iter():
        if lname(n.tag) not in ("item","entry"):continue
        title=child(n,("title",));link=child(n,("link",))
        if not link:
            for c in list(n):
                if lname(c.tag)=="link":
                    link=c.attrib.get("href","")
                    if c.attrib.get("rel","alternate") in ("alternate",""):break
        summary=child(n,("description","summary","content","encoded"))
        pub=child(n,("pubdate","published","updated","date"));d=parse_date(pub)
        source_node=next((c for c in list(n) if lname(c.tag)=="source"),None)
        publisher="".join(source_node.itertext()).strip() if source_node is not None else ""
        publisher_url=source_node.attrib.get("url","") if source_node is not None else ""
        if title or link:
            out.append({"source_id":f[0],"source":f[1],"source_type":f[3],"priority":f[4],
                "publisher":html.unescape(publisher) or f[1],"publisher_url":publisher_url,
                "title":html.unescape(re.sub(r"<[^>]+>"," ",title)).strip(),
                "url":urljoin(f[2],html.unescape(link.strip())),
                "summary":re.sub(r"\s+"," ",html.unescape(re.sub(r"<[^>]+>"," ",summary))).strip()[:4000],
                "published":d.isoformat().replace("+00:00","Z") if d else None,"_date":d})
    return out
class CertParser(HTMLParser):
    def __init__(self):super().__init__();self.a=None;self.rows=[]
    def handle_starttag(self,t,a):
        if t.lower()=="a":
            href=dict(a).get("href","")
            if "VLCODE=" in href:self.a={"url":urljoin("https://www.cert-in.org.in/",href),"text":""}
    def handle_data(self,d):
        if self.a is not None:self.a["text"]+=d
    def handle_endtag(self,t):
        if t.lower()=="a" and self.a is not None:
            x=self.a;self.a=None;title=re.sub(r"\s+"," ",x["text"]).strip()
            if title and re.search(r"CIAD-|CIVN-|CICA-",title):self.rows.append({"title":title,"url":x["url"]})
def topics(s):
    rules={"ransomware":r"ransomware|extortion","apt_intrusion":r"\bapt\b|threat actor|espionage|intrusion|campaign",
    "active_exploitation":r"zero.day|actively exploited|in.the.wild|exploitation","identity":r"identity|credential|authentication|privilege escalation|oauth|token theft",
    "cloud":r"\bcloud\b|kubernetes|container|serverless","phishing":r"phishing|social engineering|business email compromise",
    "ai_threat":r"agentic|artificial intelligence|\bai\b|llm|deepfake","supply_chain":r"supply.chain|dependency confusion|package repository",
    "edge_vpn":r"vpn|firewall|gateway|edge device|webshell","malware_botnet":r"malware|botnet|trojan|backdoor|infostealer"}
    return [k for k,p in rules.items() if re.search(p,s,re.I)]
class ArticleText(HTMLParser):
    """Conservative article text and security-reference link extraction."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.skip=0;self.capture=False;self.buf=[];self.paragraphs=[];self.meta=[]
        self.links=[];self.anchor=None
    def handle_starttag(self,tag,attrs):
        a=dict(attrs);t=tag.lower()
        if t in ("script","style","noscript","svg","nav","footer","header","aside","form"):self.skip+=1
        if t=="meta" and (a.get("name","").lower() in ("description","og:description") or a.get("property","").lower()=="og:description"):
            value=a.get("content","").strip()
            if value:self.meta.append(value)
        if t=="a" and a.get("href"):self.anchor={"href":a.get("href"),"text":""}
        if t in ("p","li"):self.capture=True;self.buf=[]
    def handle_endtag(self,tag):
        t=tag.lower()
        if t in ("script","style","noscript","svg","nav","footer","header","aside","form"):self.skip=max(0,self.skip-1)
        if t=="a" and self.anchor is not None:
            link=self.anchor;self.anchor=None;link["text"]=re.sub(r"\s+"," ",link["text"]).strip()
            if link["href"]:self.links.append(link)
        if t in ("p","li") and self.capture:
            value=re.sub(r"\s+"," "," ".join(self.buf)).strip()
            if len(value)>=55 and value not in self.paragraphs:self.paragraphs.append(value)
            self.capture=False;self.buf=[]
    def handle_data(self,data):
        if self.skip==0:
            if self.capture:self.buf.append(data.strip())
            if self.anchor is not None:self.anchor["text"]+=data.strip()


PROMOTIONAL_TEXT = re.compile(
    r"^(?:discover why\b|learn what\b|start your (?:free )?trial\b|"
    r"try (?:our|the)\b|download (?:our|the|a)\b|subscribe\b|"
    r"sponsored\b|advertisement\b|advertising\b|"
    r"book a demo\b|get your free\b|find out more about our\b)",
    re.I,
)

def is_promotional_text(value):
    """Exclude obvious sponsored/lead-generation copy from technical context."""
    return bool(PROMOTIONAL_TEXT.search(str(value or "").strip()))


def normalize_story_text(value):
    return re.sub(r"[^a-z0-9]+"," ",str(value or "").lower()).strip()

def enrich_page(url,title=""):
    """Fetch readable article text plus candidate security/advisory links."""
    try:
        if not isinstance(url,str) or not url.startswith("https://"):return {"status":"not_attempted","details":"","references":[]}
        req=urllib.request.Request(url,headers={"User-Agent":UA,"Accept":"text/html,application/xhtml+xml"})
        with urllib.request.urlopen(req,timeout=8) as response:
            if response.status!=200:return {"status":"http_error","details":"","references":[]}
            raw=response.read(1_500_000);charset=response.headers.get_content_charset() or "utf-8";resolved=response.geturl()
        parser=ArticleText();parser.feed(raw.decode(charset,errors="replace"))
        title_norm=normalize_story_text(title);parts=parser.meta[:1]+parser.paragraphs[:18];cleaned=[]
        for part in parts:
            part=re.sub(r"\s+"," ",part).strip();norm=normalize_story_text(part)
            if not part or is_promotional_text(part):continue
            if title_norm and norm and difflib.SequenceMatcher(None,norm,title_norm).ratio()>=0.94:continue
            if re.search(r"comprehensive up-to-date news coverage|aggregated from sources all over the world by google news",part,re.I):continue
            if len(part)>45 and part not in cleaned:cleaned.append(part)
        text_value="\n\n".join(cleaned);base_host=urlparse(resolved).netloc.lower();references=[]
        for link in parser.links:
            href=urljoin(resolved,html.unescape(link.get("href","")).strip());label=link.get("text","")
            host=urlparse(href).netloc.lower()
            if not href.startswith("https://") or not host or host==base_host:continue
            if re.search(r"security|advisory|bulletin|CVE-\d{4}-|patch|release notes|fixed version|vulnerability|hotfix",label+" "+href,re.I):
                if href not in [x["url"] for x in references]:references.append({"label":label[:180] or "Vendor/security reference","url":href})
        return {"status":"enriched" if len(text_value)>=250 else "limited","details":text_value[:9000],"resolved_url":resolved,"references":references[:8]}
    except Exception as exc:return {"status":"fetch_failed","details":"","references":[],"error":type(exc).__name__}

def extract_specific_remediation(text_value):
    """Accept only actionable source sentences with concrete version/configuration evidence."""
    if not text_value:return []
    generic=re.compile(r"apply mitigations? in accordance with|apply mitigations? per (?:the )?vendor|follow (?:the )?vendor (?:instructions|guidance|recommendations)|refer to (?:the )?(?:vendor|security) advisory|consult (?:the )?vendor|contact (?:the )?vendor|apply (?:the )?latest (?:security )?updates?|patch (?:all )?affected systems?|apply (?:security )?patches? (?:to|on) (?:all )?affected systems?|keep (?:your )?systems? up to date|install the latest updates?|update to the latest version",re.I)
    action=re.compile(r"\b(?:upgrade|update)\s+(?:to|all|the|affected)\b|\b(?:install|apply|deploy|disable|block|restrict|remove|uninstall|revoke|rotate|reset|isolate|turn off|configure|set|enable|rollback)\s+(?:the|all|any|affected|this|these|those|SMBv?\d|SMB|RDP|MFA|TLS|KB|version|security|latest|v?\d)\b|\b(?:upgrade|update)\s+(?-i:[A-Z])[A-Za-z0-9_.-]*(?:\s+(?-i:[A-Z])[A-Za-z0-9_.-]*){0,3}\s+to\s+(?:version|v?\d)|\b(?:fixed|patched)\s+in\b",re.I)
    concrete=re.compile(r"\b(?:version\s*v?\d|v\d+\.\d|fixed in\s+\S+|KB\d{4,}|build\s*\d|hotfix\s*\S+|patch\s*\S+|CVE-\d{4}-\d+|TCP/UDP\s*\d+|port\s+\d+|\d{1,5}/tcp|\d{1,5}/udp|SMBv?\d|RDP|MFA|PowerShell|WinRM|SSH|TLS\s*1\.[0123]|ASP\.NET|ViewStateUserKey|MAC-verified|registry key|\bHKLM\\|\bHKCU\\|\b(?:sudo|systemctl|iptables|nft|kubectl|az|aws|gcloud)\b)",re.I)
    parts=[re.sub(r"\s+"," ",x).strip(" \t-•") for x in re.split(r"(?<=[.!?])\s+|\n+",str(text_value))];results=[]
    for sentence in parts:
        if len(sentence)<35 or len(sentence)>650 or generic.search(sentence):continue
        if action.search(sentence) and concrete.search(sentence) and sentence not in results:results.append(sentence)
    return results[:5]

def kev_remediation_text(vulnerability):
    specific=extract_specific_remediation(str(vulnerability.get("requiredAction") or "").strip())
    if specific:return " ".join(specific)
    return ("No product/version-specific patch, command, configuration change or workaround is provided in this CISA KEV record. "
            "The catalogue action is general guidance, not a verified fix. Check the linked vendor advisory for the current fixed release "
            "or workaround; this report has not independently verified one.")

def enrich_records(records,max_workers=10):
    """Enrich source pages and follow a small number of explicitly linked security references."""
    if not records:return
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures={pool.submit(enrich_page,x.get("url",""),x.get("title","")):x for x in records}
        for future in as_completed(futures):
            item=futures[future]
            try:result=future.result()
            except Exception:result={"status":"fetch_failed","details":"","references":[]}
            feed_summary=item.get("summary","").strip();page_details=result.get("details","").strip()
            item["details"]=page_details if len(page_details)>len(feed_summary) else (feed_summary or "No description was exposed by the feed or retrieved source page. Review the linked advisory for authoritative details.")
            resolved=result.get("resolved_url","")
            if resolved.startswith("https://") and urlparse(resolved).netloc.lower() not in ("news.google.com","www.google.com"):item["canonical_url"]=resolved
            item["enrichment_status"]=result.get("status","unknown");item["enriched_at"]=STAMP
            item["vendor_references"]=result.get("references",[])
            if result.get("error"):item["enrichment_note"]="Source page could not be retrieved; retained feed summary."
    tasks=[]
    for item in records:
        if not item.get("cves"):continue
        for ref in (item.get("vendor_references") or [])[:2]:tasks.append((item,ref))
    if tasks:
        with ThreadPoolExecutor(max_workers=min(max_workers,8)) as pool:
            futures={pool.submit(enrich_page,ref["url"]):(item,ref) for item,ref in tasks}
            for future in as_completed(futures):
                item,ref=futures[future]
                try:result=future.result()
                except Exception:result={"details":""}
                fixes=extract_specific_remediation(result.get("details",""))
                if fixes:item.setdefault("vendor_remediation",[]).append({"source_url":result.get("resolved_url") or ref["url"],"source_label":ref.get("label") or "Vendor/security advisory","guidance":fixes[:4],"confidence":"Specific version/action wording extracted from linked security reference; analyst review required"})
    for item in records:
        evidence=item.get("details","")+"\n"+item.get("summary","");source_action=extract_specific_remediation(evidence);vendor_fixes=item.get("vendor_remediation",[])
        if vendor_fixes:
            combined=[fix for ref in vendor_fixes for fix in ref.get("guidance",[])]
            item["remediation_guidance"]=" ".join((source_action+combined)[:7])[:2400]
            item["remediation_status"]="Vendor-linked specific remediation extracted — verify affected/fixed versions"
        else:
            item["remediation_guidance"]=" ".join(source_action)[:1800] if source_action else ""
            no_patch=re.search(r"no (?:security )?(?:patch|fix|workaround) (?:is )?(?:currently )?(?:available|released)|vendor (?:has )?not (?:yet )?released (?:a )?(?:patch|fix)|patch is not yet available|(?:a )?(?:security )?fix is not yet available|fix is not currently available|in the absence of an official patch",evidence,re.I)
            gated=re.search(r"temporary workaround.{0,240}(?:signing in|sign in|support portal|customer portal)",evidence,re.I)
            if no_patch and gated:item["remediation_status"]="No vendor patch stated in source; workaround is referenced but requires vendor portal access"
            elif no_patch:item["remediation_status"]="No vendor patch stated in source"
            elif source_action:item["remediation_status"]="Specific actionable guidance extracted"
            else:item["remediation_status"]="No specific fix identified in retrieved source text" if item.get("enrichment_status")=="enriched" else "Fix status unknown — source page not fully retrieved"

def extract_iocs(s,source,url):
    found={}
    for m in IOCCTX.finditer(s):
        w=s[max(0,m.start()-100):min(len(s),m.end()+350)]
        for v in IP.findall(w):
            try:
                ip=ipaddress.ip_address(v)
                if ip.is_global:found[str(ip)]="ip"
            except ValueError:pass
        for v in DOMAIN.findall(w):
            if not v.lower().endswith((".example",".test",".invalid",".localhost")):found[v.lower()]="domain"
        for v in HASH.findall(w):found[v.lower()]="hash"
    return [{"value":v,"type":t,"source":source,"source_url":url,"confidence":"candidate near explicit IOC wording; verify against primary source"} for v,t in found.items()]

def main():
    health=[];errors=[];entries=[];business_entries=[];kev={};success=0
    try:
        kev=json.loads(fetch(KEV).decode());success+=1
        health.append({"source":"CISA KEV","status":"success","records":len(kev.get("vulnerabilities",[])),"url":KEV})
    except Exception as e:
        errors.append(f"CISA KEV: {type(e).__name__}: {e}");health.append({"source":"CISA KEV","status":"failed","records":0,"url":KEV,"error":str(e)})
    for f in FEEDS:
        try:
            rows=parse_feed(fetch(f[2]),f);entries+=rows;success+=1
            health.append({"source":f[1],"status":"success","records":len(rows),"url":f[2]})
        except Exception as e:
            errors.append(f"{f[1]}: {type(e).__name__}: {e}");health.append({"source":f[1],"status":"failed","records":0,"url":f[2],"error":str(e)})
    for bid,bname,burl in BUSINESS_FEEDS:
        try:
            bf=(bid,bname,burl,"business","medium")
            rows=parse_feed(fetch(burl),bf);business_entries+=rows;success+=1
            health.append({"source":bname,"status":"success","records":len(rows),"url":burl,"stream":"business"})
        except Exception as e:
            errors.append(f"{bname}: {type(e).__name__}: {e}");health.append({"source":bname,"status":"failed","records":0,"url":burl,"error":str(e),"stream":"business"})
    cert_url="https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST02&year="+str(NOW.year)
    try:
        p=CertParser();p.feed(fetch(cert_url).decode("utf-8",errors="replace"))
        for x in p.rows:entries.append({"source_id":"cert_in","source":"CERT-In India","source_type":"government","priority":"critical",
            "title":x["title"],"url":x["url"],"summary":"Official CERT-In index entry. Open advisory for technical details and remediation.",
            "published":None,"_date":None,"undated_certin":True})
        success+=1;health.append({"source":"CERT-In India advisory index","status":"success","records":len(p.rows),"url":cert_url,"note":"Index scrape; open advisory to confirm details"})
    except Exception as e:
        errors.append(f"CERT-In index: {type(e).__name__}: {e}");health.append({"source":"CERT-In India advisory index","status":"failed","records":0,"url":cert_url,"error":str(e)})
    cutoff=NOW-dt.timedelta(hours=72);business_cutoff=NOW-dt.timedelta(days=7);selected=[]
    for x in entries:
        body=x["title"]+" "+x["summary"];x["cves"]=extract_cves(body);x["topics"]=topics(body)
        if (x["_date"] and x["_date"]>=cutoff) or x.get("undated_certin"):selected.append(x)
    unique={}
    for x in selected:
        k=x["url"].split("#")[0].rstrip("/") or x["title"]
        if k not in unique:unique[k]=x
        else:
            y=unique[k];y["cves"]=sorted(set(y["cves"]+x["cves"]));y["topics"]=sorted(set(y["topics"]+x["topics"]))
    items=list(unique.values())
    for x in items:x.pop("_date",None)
    items.sort(key=lambda x:(x.get("published") or "",x["priority"]=="critical"),reverse=True)
    business_unique={}
    for x in business_entries:
        if not x.get("_date") or x["_date"]<business_cutoff:continue
        body=x["title"]+" "+x["summary"];category=business_category(body);status=deal_status(body)
        if is_stock_market_noise(body):continue
        if re.search(r"\b(?:stock|stocks|share price|price target|analyst rating)\b",body,re.I) and category=="Company & market updates":continue
        companies=sorted({name.lower() for name in ("CrowdStrike","Zscaler","Palo Alto Networks","Microsoft","Google","Cisco","Fortinet","Check Point","SentinelOne","Mandiant","Broadcom","VMware","IBM","Amazon","Cloudflare","Okta","Proofpoint","Tenable","Rapid7","Wiz","Rubrik","Splunk","Akamai") if re.search(re.escape(name),body,re.I)})
        event_key=("m&a:"+ "|".join(companies[:4])+":"+status.lower()) if category=="M&A" and len(companies)>=2 else category+":"+normalize_story_text(x["title"])
        record={"title":x["title"],"summary":x["summary"],"url":x["url"],"publisher":x.get("publisher") or x["source"],"published":x.get("published"),
            "category":category,"deal_status":status,"companies":companies,"related_sources":[x.get("publisher") or x["source"]],"related_urls":[x["url"]],
            "confidence":"Reported; verify material claims against company announcements and regulatory filings"}
        if event_key not in business_unique:business_unique[event_key]=record
        else:
            old=business_unique[event_key]
            if record["published"] and (not old.get("published") or record["published"]>old["published"]):
                record["related_sources"]=old["related_sources"];record["related_urls"]=old["related_urls"];business_unique[event_key]=record;old=record
            if record["publisher"] not in old["related_sources"]:old["related_sources"].append(record["publisher"])
            if record["url"] not in old["related_urls"]:old["related_urls"].append(record["url"])
    business_items=sorted(business_unique.values(),key=lambda x:x.get("published") or "",reverse=True)
    # Retrieve article-level context and follow only explicitly linked security references.
    enrich_records(items)
    enrich_records(business_items)
    # CVEs must be extracted after full-page retrieval; feed snippets alone are incomplete.
    for item in items:
        item["cves"]=extract_cves(item.get("title"),item.get("summary"),item.get("details"),
            " ".join(fix for ref in item.get("vendor_remediation",[]) for fix in ref.get("guidance",[])))
        item["cve_extraction_scope"]="title + feed summary + retrieved article + linked vendor remediation references"
        item["cve_count"]=len(item["cves"])
    for x in items:
        body=x.get("title","")+" "+x.get("summary","")+" "+x.get("details","")
        x["attack_techniques"]=sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b",body,re.I)))
    vulns=kev.get("vulnerabilities",[]) if kev else []
    recentkev=sorted([v for v in vulns if v.get("dateAdded","")>=(NOW_IST.date()-dt.timedelta(days=7)).isoformat()],key=lambda x:x.get("dateAdded",""),reverse=True)
    iocmap={}
    for x in items:
        for v in extract_iocs(x["title"]+" "+x["summary"]+" "+x.get("details",""),x["source"],x["url"]):
            key=(v["type"],v["value"])
            if key not in iocmap:iocmap[key]={**v,"related_sources":[],"related_urls":[]}
            entry=iocmap[key]
            if v["source"] not in entry["related_sources"]:entry["related_sources"].append(v["source"])
            if v["source_url"] not in entry["related_urls"]:entry["related_urls"].append(v["source_url"])
    iocs=list(iocmap.values())
    if not success:print("All feeds failed; refusing to publish.");print("\n".join(errors));return 1
    good=sum(x["status"]=="success" for x in health)
    report=Path("intel/daily")/DAY[:4]/DAY[5:7]/(DAY[8:10]+".md")
    snapshot=Path("intel/snapshots")/DAY[:4]/DAY[5:7]/(DAY[8:10]+".json")
    (ROOT/report).parent.mkdir(parents=True,exist_ok=True);(ROOT/snapshot).parent.mkdir(parents=True,exist_ok=True)
    data={"date_utc":DAY_UTC,"date_ist":DAY,"retrieved_at":STAMP,"retrieved_at_ist":STAMP_IST,"window_hours":72,"source_health":health,"successful_sources":good,"total_sources":len(health),
        "errors":errors,"business_items":business_items,"business_feed_count":len(business_items),"business_window_hours":168,"cisa_kev_catalog_count":len(vulns),"cisa_kev_catalog":vulns,"cisa_kev_added_last_7_days":recentkev,"items":items,
        "ioc_candidates":iocs,"ioc_policy":"Candidate extraction only near explicit IOC wording. Verify against original report and local context.",
        "limitations":["Public feeds are not exhaustive and can fail or change format.","CERT-In is an official index scrape, not an RSS feed; open advisory pages to confirm details.",
        "Authenticated/paid feeds are not configured.","A CVE listing or IOC match is not proof of compromise.","No automatic response actions."]}
    (ROOT/snapshot).write_text(json.dumps(data,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    latest={"date_utc":DAY_UTC,"date_ist":DAY,"retrieved_at":STAMP,"retrieved_at_ist":STAMP_IST,"snapshot":f"snapshots/{DAY[:4]}/{DAY[5:7]}/{DAY[8:10]}.json","report":f"daily/{DAY[:4]}/{DAY[5:7]}/{DAY[8:10]}.md"}
    (ROOT/"intel/latest.json").write_text(json.dumps(latest,indent=2)+"\n",encoding="utf-8")
    lines=[f"# Global Cyber Threat Radar — Automated Snapshot — {DAY} IST","",f"- Retrieved: {STAMP_IST} (UTC: {STAMP})","- Coverage: last 72 hours + undated CERT-In index entries",
        f"- Feed health: {good}/{len(health)}",f"- Advisory/research items: {len(items)}",f"- CISA KEV catalog: {len(vulns)}",f"- KEV additions last 7 days: {len(recentkev)}",f"- IOC candidates: {len(iocs)}",
        "","## Feed health","","| Source | Status | Records |","|---|---|---:|"]
    lines += [f"| {x['source']} | {x['status']} | {x['records']} |" for x in health]
    lines += ["","## CISA KEV additions — last 7 days",""]
    if recentkev:
        for v in recentkev[:40]:
            lines.append(f"- **{v.get('cveID','CVE unavailable')} — {v.get('vulnerabilityName','Name unavailable')}** | {v.get('vendorProject','unknown')} / {v.get('product','unknown')} | added {v.get('dateAdded','unknown')} | due {v.get('dueDate','not stated')} | [CISA record]({v.get('notes','https://www.cisa.gov/known-exploited-vulnerabilities-catalog')})")
            lines.append("  - Fix / remediation: "+kev_remediation_text(v))
    else:lines.append("- No additions returned, or the feed failed; check source health.")
    lines += ["","## Advisories, campaigns and research — last 72 hours",""]
    if items:
        for x in items[:100]:lines += [f"### {x['title']}",f"- Source: {x['source']} | Published: {x.get('published') or 'date not exposed in index'} | Detail enrichment: {x.get('enrichment_status','feed summary only')}",
            f"- CVEs: {', '.join(x['cves']) or 'none extracted'} | Topic signals: {', '.join(x['topics']) or 'analyst review required'}",
            f"- Summary: {x.get('summary','')[:900]}",
            f"- Technical details: {x.get('details') or x.get('summary','')[:900]}",
            f"- Fix / remediation: {x.get('remediation_guidance') or x.get('remediation_status') or 'Fix status unknown; check the linked vendor advisory for updates.'}",
            f"- [Open source item]({x['url']})",""]
    else:lines.append("No dated items returned. This does not mean no threats occurred; inspect source health.")
    lines += ["","## Cyber business & market developments — last 72 hours",""]
    if business_items:
        for x in business_items[:60]:
            lines += ["### "+x["title"],"- Category: "+x["category"]+" | Deal stage: "+x["deal_status"]+" | Publisher: "+x["publisher"]+" | Published: "+(x.get("published") or "unknown")+" | Detail enrichment: "+x.get("enrichment_status","feed summary only"),"- Summary: "+x.get("summary","")[:900],"- Business background / implications: "+(x.get("details") or x.get("summary",""))[:2500],"- Action: Not applicable as a vulnerability fix; verify deal stage and material claims against company announcements or filings.","- Evidence: [Original report]("+x["url"]+")",""]
    else:lines.append("- No business items collected; check business feed health.")
    lines += ["","## IOC candidates — analyst verification required",""]
    if iocs:
        lines += ["Extracted only near explicit IOC-related wording. Do not block without verification.","","| Type | Value | Source |","|---|---|---|"]
        lines += [f"| {x['type']} | {x['value']} | {x['source']} |" for x in iocs[:200]]
    else:lines.append("No safe IOC candidates extracted. No IOC query generated; no placeholder values inserted.")
    lines += ["","## Behavior-based detection engineering","",
        "Generic behavior hunts are maintained separately and are not attributed to a specific campaign without source evidence:",
        "- [Suspicious PowerShell/process execution](../../../detection-queries/kql/threat-hunting/windows_suspicious_execution.kql)",
        "- [Scheduled-task/service persistence](../../../detection-queries/kql/threat-hunting/windows_persistence_changes.kql)",
        "- [Entra privileged role and credential changes](../../../detection-queries/kql/threat-hunting/entra_privilege_changes.kql)",
        "","## Collection errors",""]
    lines += [f"- {e}" for e in errors] or ["- None."]
    lines += ["","## Analyst workflow","",
        "1. Match KEV/advisories to asset inventory, versions and internet exposure.",
        "2. Verify exploit status, affected versions and remediation against primary vendor/CERT advisories.",
        "3. Derive behavior hunts from documented TTPs; map ATT&CK only when supported by evidence.",
        "4. Verify candidate IOCs against original source, freshness and local telemetry.",
        "5. Keep queries Draft until schema, syntax, positive/negative tests and tuning are recorded.",
        "","## Limitations","",
        "- Broad public-source baseline, not exhaustive global intelligence.",
        "- ThreatFox, OTX, GreyNoise and Shadowserver are not enabled; review credentials and provider terms before integration.",
        "- Business discovery uses a wider 7-day window; Google News results are reported leads and require company-announcement or filing verification.",
        "- Feed failures and quiet periods do not mean absence of threats; report timestamps are IST and machine timestamps in JSON are UTC.",
        "",f"Raw evidence: [JSON snapshot](../../../snapshots/{DAY[:4]}/{DAY[5:7]}/{DAY[8:10]}.json)."]
    (ROOT/report).write_text("\n".join(lines)+"\n",encoding="utf-8")
    enriched_threats=sum(x.get("enrichment_status")=="enriched" for x in items)
    enriched_business=sum(x.get("enrichment_status")=="enriched" for x in business_items)
    print(f"Source-page enrichment: threats {enriched_threats}/{len(items)}; business {enriched_business}/{len(business_items)}")
    print(f"IOC correlations: {len(iocs)} unique candidate indicators")
    if iocs:
        qp=Path("detection-queries/generated")/DAY[:4]/DAY[5:7]/f"candidate_ioc_hunt_{DAY}.kql"
        (ROOT/qp).parent.mkdir(parents=True,exist_ok=True)
        domains=[x["value"] for x in iocs if x["type"]=="domain"][:200];ips=[x["value"] for x in iocs if x["type"]=="ip"][:200];hashes=[x["value"] for x in iocs if x["type"]=="hash"][:200]
        q=f"""// ID: GCI-KQL-IOC-{DAY.replace('-','')}
// Title: Candidate IOC network and file hunt
// Platform: Microsoft Defender XDR / Sentinel
// Type: Threat-intelligence hunt; analyst verification required
// Data source: DeviceNetworkEvents, DeviceFileEvents
// Required fields: Timestamp, DeviceName, RemoteUrl, RemoteIP, SHA256, SHA1, MD5
// Maturity: Draft
// False positives: Shared hosting, stale indicators, benign redirects and common software hashes
// Tuning: Verify each value against the primary report before use
let Domains = dynamic({json.dumps(domains)});
let IPs = dynamic({json.dumps(ips)});
let Hashes = dynamic({json.dumps(hashes)});
union
(DeviceNetworkEvents | where Timestamp > ago(7d) | where (isnotempty(RemoteUrl) and RemoteUrl has_any (Domains)) or (isnotempty(RemoteIP) and RemoteIP in (IPs)) | project Timestamp, DeviceName, EventType="Network", Indicator=coalesce(RemoteUrl,RemoteIP), InitiatingProcessFileName, InitiatingProcessCommandLine),
(DeviceFileEvents | where Timestamp > ago(7d) | where SHA256 in (Hashes) or SHA1 in (Hashes) or MD5 in (Hashes) | project Timestamp, DeviceName, EventType="File", Indicator=coalesce(SHA256,SHA1,MD5), InitiatingProcessFileName, InitiatingProcessCommandLine)
| order by Timestamp desc
"""
        (ROOT/qp).write_text(q,encoding="utf-8");print("Wrote candidate IOC query",qp)
    print(f"Wrote {report} and {snapshot}; healthy sources {good}/{len(health)}; items {len(items)}; KEV {len(recentkev)}; IOC candidates {len(iocs)}")
    if errors:print(f"Partial collection: {len(errors)} source failures; see report.")
    return 0
if __name__=="__main__":sys.exit(main())
