#!/usr/bin/env python3
"""Multi-source public cyber-intelligence collector. No automated response actions."""
import datetime as dt, email.utils, html, ipaddress, json, re, sys, urllib.request, difflib, time, socket, http.client, os
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlencode

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
("cert_eu","CERT-EU","https://cert.europa.eu/publications/security-advisories-rss","government","medium"),
("sans_isc","SANS Internet Storm Center","https://isc.sans.edu/rssfeed.xml","research","high"),
("bleepingcomputer","BleepingComputer","https://www.bleepingcomputer.com/feed/","news","medium"),
("thehackernews","The Hacker News","https://thehackernews.com/feeds/posts/default","news","medium"),
("talos","Cisco Talos","https://blog.talosintelligence.com/rss/","research","high"),
("unit42","Palo Alto Unit 42","https://unit42.paloaltonetworks.com/feed/","research","high"),
("google_ti","Google Threat Intelligence / Mandiant","https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v","research","critical"),

("cisco_psirt","Cisco PSIRT","https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml","vendor","critical"),
("fortinet_psirt","Fortinet PSIRT","https://www.fortiguard.com/rss/ir.xml","vendor","high"),
("google_security","Google Security Blog","https://blog.google/security/rss/","vendor","high"),
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

IOCCTX=re.compile(r"(?i)\b(iocs?|indicators? of compromise|c2|command[- ]and[- ]control|callback|malicious (?:ip|domain|url|hash)|payload hash|sha(?:256|1|512)|ip address|domain names?|email address|file name|filename)\b")
IP=re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6=re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
DOMAIN=re.compile(r"(?i)(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|biz|xyz|top|ru|cn|uk|in|io|dev|app|cloud|site|online|live|me|co|gov|edu|eu|de|fr|br|au|ca|jp|tech|pro|work|shop|store|click|link|pw|cc|to|ws)(?![\w.-])")
URLIOC=re.compile(r"https?://[^\s<>\"']+",re.I)
EMAILIOC=re.compile(r"(?i)\b[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}\b")
FILENAMEIOC=re.compile(r"(?i)\b[A-Z0-9_.-]{1,120}\.(?:exe|dll|sys|ps1|psm1|bat|cmd|vbs|js|jse|hta|scr|iso|lnk|jar|elf|so|dylib|docm|xlsm|zip|7z)\b")
HASH=re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")

def resolve_public_addresses(host,port=443):
    """Resolve a host once and return only globally routable addresses."""
    try:
        literal=ipaddress.ip_address(host)
        addresses=[literal]
    except ValueError:
        try:
            answers=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ValueError("Destination DNS resolution failed") from exc
        addresses=[]
        for answer in answers:
            try:
                addresses.append(ipaddress.ip_address(answer[4][0].split("%",1)[0]))
            except ValueError as exc:
                raise ValueError("Destination DNS returned an invalid address") from exc
    if not addresses:
        raise ValueError("Destination did not resolve to an IP address")
    if any(not address.is_global for address in addresses):
        raise ValueError("Destination resolves to a non-public IP address")
    return addresses

def validate_public_https_url(url):
    """Reject non-HTTPS, credentialed, nonstandard-port and non-public destinations."""
    if not isinstance(url,str) or len(url)>4096:
        raise ValueError("URL is missing or exceeds the permitted length")
    parsed=urlparse(url)
    if parsed.scheme.lower()!="https" or not parsed.hostname:
        raise ValueError("Only absolute HTTPS URLs are permitted")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentialed URLs are not permitted")
    try:
        port=parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL port") from exc
    if port not in (None,443):
        raise ValueError("Only HTTPS port 443 is permitted")
    resolve_public_addresses(parsed.hostname.rstrip("."),port or 443)
    return url

class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to the exact public IP that was validated; retain hostname TLS checks."""
    def connect(self):
        addresses=resolve_public_addresses(self.host,self.port)
        last_error=None
        for address in addresses:
            raw=None
            try:
                raw=socket.create_connection((str(address),self.port),self.timeout,self.source_address)
                if self._tunnel_host:
                    self.sock=raw
                    self._tunnel()
                    raw=self.sock
                self.sock=self._context.wrap_socket(raw,server_hostname=self.host)
                return
            except OSError as exc:
                last_error=exc
                if raw is not None:
                    try: raw.close()
                    except OSError: pass
        if last_error: raise last_error
        raise OSError("No usable public destination address")

class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self,req):
        return self.do_open(PinnedHTTPSConnection,req,context=self._context)

class PublicHTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Revalidate every redirect target before urllib follows it."""
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        validate_public_https_url(newurl)
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def safe_https_open(request,timeout):
    target=request.full_url if isinstance(request,urllib.request.Request) else str(request)
    validate_public_https_url(target)
    # Disable environment proxies so the validated destination is the actual peer.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),PublicHTTPSRedirectHandler(),PinnedHTTPSHandler())
    response=opener.open(request,timeout=timeout)
    validate_public_https_url(response.geturl())
    return response

RETRYABLE_HTTP_STATUS={408,425,429,500,502,503,504}

def request_url(url,headers,timeout,max_bytes=None,max_attempts=4):
    """Fetch a complete response with bounded retries for transient network/service errors."""
    req=urllib.request.Request(url,headers=headers)
    for attempt in range(max_attempts):
        try:
            with safe_https_open(req,timeout=timeout) as response:
                if response.status!=200: raise RuntimeError("HTTP "+str(response.status))
                raw=response.read(max_bytes) if max_bytes else response.read()
                charset=response.headers.get_content_charset() or "utf-8"
                resolved=response.geturl()
                return raw,charset,resolved
        except urllib.error.HTTPError as exc:
            if exc.code not in RETRYABLE_HTTP_STATUS or attempt>=max_attempts-1:
                raise
            retry_after=exc.headers.get("Retry-After","") if exc.headers else ""
            delay=min(30,max(0,int(retry_after))) if str(retry_after).isdigit() else min(2**attempt,8)
        except (urllib.error.URLError,socket.timeout,TimeoutError,http.client.IncompleteRead,ConnectionError) as exc:
            if attempt>=max_attempts-1:
                raise
            delay=min(2**attempt,8)
        time.sleep(delay)
    raise RuntimeError("Request exhausted retry attempts")

def fetch(url,timeout=25,max_attempts=4):
    raw,_,_=request_url(url,{"User-Agent":UA,"Accept":"application/rss+xml, application/atom+xml, application/xml, text/xml, text/html, application/json, */*"},timeout=timeout,max_attempts=max_attempts)
    return raw

def load_source_health_state():
    path=ROOT/"intel/source-health-state.json"
    try:
        value=json.loads(path.read_text(encoding="utf-8"))
        sources=value.get("sources",{}) if isinstance(value,dict) else {}
        return sources if isinstance(sources,dict) else {}
    except (OSError,ValueError,TypeError):
        return {}

def record_source_health(state,source,url,status,records,started,error=None,stream=None,note=None):
    previous=state.get(source,{})
    attempted=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
    ok=status=="success"
    try: previous_failures=max(0,int(previous.get("consecutive_failures",0) or 0))
    except (TypeError,ValueError): previous_failures=0
    count=max(0,int(records or 0))
    entry={"source":source,"status":status,
        "collection_result":("success_with_records" if count else "success_empty") if ok else "failed",
        "records":count,"url":url,"last_attempt_at":attempted,
        "last_success_at":attempted if ok else previous.get("last_success_at"),
        "duration_ms":max(0,int((time.perf_counter()-started)*1000)),
        "consecutive_failures":0 if ok else previous_failures+1}
    if error: entry["error"]=str(error)[:600]
    if stream: entry["stream"]=stream
    if note: entry["note"]=note
    state[source]={k:entry[k] for k in ("last_success_at","consecutive_failures","last_attempt_at","duration_ms","status","collection_result","records","error") if k in entry}
    return entry

def save_source_health_state(state):
    path=ROOT/"intel/source-health-state.json"
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps({"schema_version":1,"updated_at":STAMP,"sources":state},indent=2,ensure_ascii=False)+"\n",encoding="utf-8")

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
        raw,charset,resolved=request_url(url,{"User-Agent":UA,"Accept":"text/html,application/xhtml+xml"},timeout=8,max_bytes=1_500_000)
        parser=ArticleText();parser.feed(raw.decode(charset,errors="replace"))
        title_norm=normalize_story_text(title);parts=parser.meta[:1]+parser.paragraphs[:18];cleaned=[]
        for part in parts:
            part=re.sub(r"\s+"," ",part).strip();norm=normalize_story_text(part)
            if not part or is_promotional_text(part):continue
            if title_norm and norm and difflib.SequenceMatcher(None,norm,title_norm).ratio()>=0.94:continue
            if re.search(r"comprehensive up-to-date news coverage|aggregated from sources all over the world by google news|identify and remediate systems affected by this advisory|for more details on how to apply this update|refer to the cve page\\(s\\) listed in the references section",part,re.I):continue
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
    action=re.compile(r"\b(?:upgrade|update)\s+(?:to|all|the|affected)\b|\breplace\s+(?:it|the [A-Za-z0-9_.-]+)\s+with\b|\b(?:install|apply|deploy|disable|block|restrict|remove|uninstall|revoke|rotate|reset|isolate|turn off|configure|set|enable|rollback)\s+(?:the|all|any|affected|this|these|those|SMBv?\d|SMB|RDP|MFA|TLS|KB|version|security|latest|v?\d)\b|\b(?:upgrade|update)\s+(?-i:[A-Z])[A-Za-z0-9_.-]*(?:\s+(?-i:[A-Z])[A-Za-z0-9_.-]*){0,3}\s+to\s+(?:version|v?\d)|\b(?:fixed|patched)\s+in\b",re.I)
    concrete=re.compile(r"\b(?:version\s*v?\d|v\d+\.\d|fixed in\s+\S+|KB\d{4,}|build\s*\d|hotfix\s*\S+|patch\s*\S+|CVE-\d{4}-\d+|TCP/UDP\s*\d+|port\s+\d+|\d{1,5}/tcp|\d{1,5}/udp|SMBv?\d|RDP|MFA|PowerShell|WinRM|SSH|TLS\s*1\.[0123]|ASP\.NET|ViewStateUserKey|MAC-verified|registry key|\bHKLM\\|\bHKCU\\|\b(?:sudo|systemctl|iptables|nft|kubectl|az|aws|gcloud)\b)",re.I)
    parts=[re.sub(r"\s+"," ",x).strip(" \t-•") for x in re.split(r"(?<=[.!?])\s+|\n+",str(text_value))];results=[]
    for index,sentence in enumerate(parts):
        if "such as follows" in sentence.lower() and index+1<len(parts):
            sentence=sentence.rstrip(" -:")+" Recommended configuration: "+parts[index+1]
        if len(sentence)<35 or len(sentence)>650 or generic.search(sentence):continue
        if action.search(sentence) and concrete.search(sentence) and sentence not in results:results.append(sentence)
    return results[:5]

def extract_candidate_fixed_releases(text_value,source_url,source_label="CISA-linked vendor advisory"):
    """Extract explicit release statements as candidates only; never assert applicability or verification."""
    if not text_value or not isinstance(source_url,str) or not source_url.startswith("https://"):
        return []
    version=r"([0-9]+(?:\.[0-9A-Za-z-]+){1,4})"
    patterns=[
        re.compile(r"\b(?:fixed|patched)\s+in\s+(?:version\s+|v)?"+version+r"\b",re.I),
        re.compile(r"\b(?:upgrade|update)\s+to\s+(?:version\s+|v)"+version+r"\b",re.I),
    ]
    sentences=[re.sub(r"\s+"," ",x).strip(" \t-•") for x in re.split(r"(?<=[.!?])\s+|\n+",str(text_value))]
    found=[];seen=set()
    for sentence in sentences:
        if len(sentence)<20 or len(sentence)>650:
            continue
        for pattern in patterns:
            for match in pattern.finditer(sentence):
                release=match.group(1)
                key=(release,sentence.lower(),source_url)
                if key in seen:continue
                seen.add(key)
                found.append({
                    "version":release,"statement":sentence,"source_url":source_url,
                    "source_label":source_label,"verification_status":"NOT_VERIFIED",
                    "analyst_verified":False,
                    "confidence":"Explicit fixed/upgrade release wording extracted; product, branch and affected-build applicability not verified"
                })
    return found[:8]

def kev_remediation_text(vulnerability):
    vendor_fixes=[fix for ref in vulnerability.get("vendor_remediation",[]) for fix in ref.get("guidance",[])]
    if vendor_fixes:return " ".join(vendor_fixes[:6])+" (linked vendor advisory; verify affected/fixed versions and deployment)"
    specific=extract_specific_remediation(str(vulnerability.get("requiredAction") or "").strip())
    if specific:return " ".join(specific)
    return ("No product/version-specific patch, command, configuration change or workaround is provided in this CISA KEV record. "
            "The catalogue action is general guidance, not a verified fix. Check the linked vendor advisory for the current fixed release "
            "or workaround; this report has not independently verified one.")

def build_remediation_evidence(item,evidence,source_action,vendor_fixes,no_patch,gated):
    """Attach an explicit, dated evidence state without claiming automated verification."""
    sources=[]
    for url in [item.get("url")]+[ref.get("source_url") for ref in (vendor_fixes or [])]:
        if isinstance(url,str) and url.startswith("https://") and url not in sources:sources.append(url)
    if vendor_fixes:
        state="vendor_guidance_unverified"
    elif no_patch and gated:
        state="source_reports_workaround_portal"
    elif no_patch:
        state="source_reports_no_fix"
    elif source_action:
        state="specific_action_unverified"
    elif item.get("enrichment_status")=="enriched":
        state="not_found_in_reviewed_evidence"
    else:
        state="not_reviewed"
    candidates=[]
    for ref in (vendor_fixes or []):
        for candidate in ref.get("candidate_fixed_releases",[]):
            if isinstance(candidate,dict) and isinstance(candidate.get("source_url"),str) and candidate["source_url"].startswith("https://"):
                candidates.append(candidate)
    return {"state":state,"checked_at":STAMP,"evidence_sources":sources[:8],
        "fixed_version":None,"candidate_fixed_releases":candidates[:12],"analyst_verified":False,
        "verification_note":"Automated extraction only. Candidate releases are NOT VERIFIED; confirm exact product, affected branch/build, vendor applicability and deployment before treating any release as fixed."}

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
            if "category" in item:
                title_norm=normalize_story_text(item.get("title",""))
                details_norm=normalize_story_text(item.get("details",""))
                similarity=difflib.SequenceMatcher(None,title_norm,details_norm).ratio() if title_norm and details_norm else 0
                if item["enrichment_status"]!="enriched" or similarity>=0.78:
                    item["enrichment_status"]="limited"
                    item["business_context_quality"]="limited"
                    item["business_context_note"]="Article-level context was not independently retrieved; the card uses only the publisher feed snippet."
                else:
                    item["business_context_quality"]="article-enriched"
                    item["business_context_note"]="Readable article text retrieved; verify material claims against the primary company or regulator announcement."
            item["vendor_references"]=result.get("references",[])
            if result.get("error"):item["enrichment_note"]="Source page could not be retrieved; retained feed summary."
    # Detect CVEs from the retrieved article before deciding whether to follow vendor links.
    for item in records:
        item["cves"]=extract_cves(item.get("title"),item.get("summary"),item.get("details"))
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
        no_patch=bool(re.search(r"no (?:security )?(?:patch|fix|workaround) (?:is )?(?:currently )?(?:available|released)|vendor (?:has )?not (?:yet )?released (?:a )?(?:patch|fix)|patch is not yet available|(?:a )?(?:security )?fix is not yet available|fix is not currently available|in the absence of an official patch",evidence,re.I))
        gated=bool(re.search(r"temporary workaround.{0,240}(?:signing in|sign in|support portal|customer portal)",evidence,re.I))
        if vendor_fixes:
            combined=[fix for ref in vendor_fixes for fix in ref.get("guidance",[])]
            item["remediation_guidance"]=" ".join((source_action+combined)[:7])[:2400]
            item["remediation_status"]="Vendor-linked specific remediation extracted — verify affected/fixed versions"
        else:
            item["remediation_guidance"]=" ".join(source_action)[:1800] if source_action else ""
            if no_patch and gated:item["remediation_status"]="No vendor patch stated in source; workaround is referenced but requires vendor portal access"
            elif no_patch:item["remediation_status"]="Source states no patch/fix is available; verify current vendor status"
            elif source_action:item["remediation_status"]="Specific actionable guidance extracted"
            else:item["remediation_status"]="No specific fix identified in retrieved source text" if item.get("enrichment_status")=="enriched" else "Fix status unknown — source page not fully retrieved"
        item["remediation_evidence"]=build_remediation_evidence(item,evidence,source_action,vendor_fixes,no_patch,gated)

EPSS_API="https://api.first.org/data/v1/epss"
NVD_API="https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_ATTRIBUTION="EPSS by FIRST.org / Empirical Security"

def enrich_epss(records):
    """Enrich CVEs in current KEV additions and advisory records using bounded lookups."""
    cves=sorted({str(c).upper() for record in records
        for c in (record.get("cves",[]) or ([record.get("cveID")] if record.get("cveID") else []))
        if CVE.fullmatch(str(c).upper())})
    lookup={};errors=[];batches=[];batch=[];length=0
    for cve in cves:
        extra=len(cve)+(1 if batch else 0)
        if batch and length+extra>1800:
            batches.append(batch);batch=[];length=0
        batch.append(cve);length+=extra
    if batch:batches.append(batch)
    for group in batches:
        url=EPSS_API+"?"+urlencode({"cve":",".join(group)})
        try:
            raw,_,_=request_url(url,{"User-Agent":UA,"Accept":"application/json"},timeout=20,max_bytes=2_000_000)
            payload=json.loads(raw.decode("utf-8"))
            if payload.get("status")!="OK" or not isinstance(payload.get("data"),list):
                raise ValueError("Unexpected FIRST EPSS response schema")
            for row in payload["data"]:
                if not isinstance(row,dict):continue
                cve=str(row.get("cve","")).upper()
                if cve not in group:continue
                try:
                    score=float(row.get("epss"));percentile=float(row.get("percentile"))
                    score_date=dt.date.fromisoformat(str(row.get("date",""))).isoformat()
                except (TypeError,ValueError):
                    continue
                if not (0.0<=score<=1.0 and 0.0<=percentile<=1.0):continue
                lookup[cve]={"cve":cve,"score":score,"percentile":percentile,"score_date":score_date,
                    "source":EPSS_ATTRIBUTION,"source_url":EPSS_API}
        except Exception as exc:
            errors.append(type(exc).__name__+": "+str(exc)[:240])
    for record in records:
        ids=record.get("cves",[]) or ([record.get("cveID")] if record.get("cveID") else [])
        ids=sorted({str(c).upper() for c in ids if CVE.fullmatch(str(c).upper())})
        record["epss_scores"]=[lookup[c] for c in ids if c in lookup]
        if not ids:record["epss_status"]="not_applicable_no_cve"
        elif record["epss_scores"] and any(c not in lookup for c in ids):record["epss_status"]="partially_available"
        elif errors and not record["epss_scores"]:record["epss_status"]="lookup_failed"
        elif record["epss_scores"]:record["epss_status"]="available"
        elif errors:record["epss_status"]="lookup_failed"
        else:record["epss_status"]="no_score_returned"
        record["epss_retrieved_at"]=STAMP
    return {"provider":EPSS_ATTRIBUTION,"source_url":EPSS_API,"retrieved_at":STAMP,
        "requested_cves":len(cves),"matched_cves":len(lookup),"batch_count":len(batches),
        "status":"partial" if errors and lookup else ("failed" if errors else "success"),
        "errors":errors[:10],
        "interpretation":"EPSS estimates the probability of exploitation in the next 30 days; it is not proof of exploitation or an organisation-specific risk score."}

def format_epss_context(record):
    scores=record.get("epss_scores",[])
    if scores:
        return "; ".join("%s %.3f (%.1f%% next-30-day estimate), percentile %.3f, dated %s" %
            (x["cve"],x["score"],x["score"]*100,x["percentile"],x["score_date"]) for x in scores)
    if record.get("epss_status")=="no_score_returned":return "No EPSS score returned"
    if record.get("epss_status")=="lookup_failed":return "EPSS lookup failed"
    if record.get("epss_status")=="partially_available":return "EPSS partially available"
    return "EPSS unavailable / not applicable"

def enrich_nvd_cvss(records,max_records=15):
    """Retrieve NVD CVSS metrics for recent KEV entries, respecting unauthenticated rate limits."""
    cves=sorted({str(r.get("cveID","")).upper() for r in records if CVE.fullmatch(str(r.get("cveID","")).upper())})[:max_records]
    api_key=os.environ.get("NVD_API_KEY","").strip()
    headers={"User-Agent":UA,"Accept":"application/json"}
    if api_key:headers["apiKey"]=api_key
    lookup={};errors=[]
    for index,cve in enumerate(cves):
        if index:time.sleep(0.7 if api_key else 6.1)
        try:
            url=NVD_API+"?"+urlencode({"cveId":cve})
            raw,_,_=request_url(url,headers,timeout=12,max_bytes=2_000_000,max_attempts=2)
            payload=json.loads(raw.decode("utf-8"))
            rows=payload.get("vulnerabilities")
            if not isinstance(rows,list):raise ValueError("Unexpected NVD CVE API response schema")
            match=next((x.get("cve",{}) for x in rows if isinstance(x,dict) and x.get("cve",{}).get("id")==cve),None)
            if not match:
                lookup[cve]={"status":"not_found","source_url":"https://nvd.nist.gov/vuln/detail/"+cve}
                continue
            metrics=match.get("metrics",{}) if isinstance(match.get("metrics"),dict) else {}
            chosen=None
            for key in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                candidates=metrics.get(key,[])
                if not isinstance(candidates,list):continue
                candidates=sorted((x for x in candidates if isinstance(x,dict)),key=lambda x:0 if x.get("type")=="Primary" else 1)
                for metric in candidates:
                    data=metric.get("cvssData",{})
                    if not isinstance(data,dict):continue
                    try:score=float(data.get("baseScore"))
                    except (TypeError,ValueError):continue
                    if not 0.0<=score<=10.0:continue
                    severity=str(data.get("baseSeverity") or metric.get("baseSeverity") or "").upper()
                    if severity and severity not in ("LOW","MEDIUM","HIGH","CRITICAL"):severity=""
                    chosen={"version":str(data.get("version") or key.replace("cvssMetricV","")),
                        "base_score":score,"severity":severity or None,"vector":str(data.get("vectorString") or ""),
                        "source":str(metric.get("source") or "NVD"),"source_type":str(metric.get("type") or "Unknown"),
                        "nvd_last_modified":match.get("lastModified"),"nvd_status":match.get("vulnStatus"),
                        "source_url":"https://nvd.nist.gov/vuln/detail/"+cve}
                    break
                if chosen:break
            if chosen:lookup[cve]={"status":"available","metric":chosen}
            elif metrics:lookup[cve]={"status":"invalid_metric","source_url":"https://nvd.nist.gov/vuln/detail/"+cve}
            else:lookup[cve]={"status":"not_scored_in_nvd","source_url":"https://nvd.nist.gov/vuln/detail/"+cve}
        except Exception as exc:
            errors.append(cve+": "+type(exc).__name__+": "+str(exc)[:180])
            lookup[cve]={"status":"lookup_failed","source_url":"https://nvd.nist.gov/vuln/detail/"+cve}
    for record in records:
        cve=str(record.get("cveID","")).upper()
        result=lookup.get(cve)
        record["cvss"]=result.get("metric") if result and result.get("status")=="available" else None
        record["cvss_status"]=result.get("status","not_applicable_no_cve") if result else "not_requested"
        record["cvss_retrieved_at"]=STAMP
    available=sum(x.get("status")=="available" for x in lookup.values())
    return {"provider":"NIST National Vulnerability Database","source_url":NVD_API,"retrieved_at":STAMP,
        "requested_cves":len(cves),"scored_cves":available,"api_key_configured":bool(api_key),
        "unauthenticated_delay_seconds":None if api_key else 6.1,"errors":errors[:10],
        "status":"partial" if errors and available else ("failed" if errors else "success"),
        "interpretation":"CVSS describes technical severity, not exploitation probability or organisation-specific risk. NVD may have no score or may not have completed analysis."}

def format_cvss_context(record):
    metric=record.get("cvss")
    if metric:
        return "CVSS %s %.1f %s; vector %s; metric source %s (%s); NVD status %s; record updated %s" % (
            metric.get("version","unknown"),metric.get("base_score",0),metric.get("severity") or "severity not stated",
            metric.get("vector") or "vector not supplied",metric.get("source") or "source not stated",metric.get("source_type") or "type not stated",metric.get("nvd_status") or "status not stated",metric.get("nvd_last_modified") or "date not stated")
    states={"not_scored_in_nvd":"NVD has no CVSS metric","lookup_failed":"NVD lookup failed",
        "invalid_metric":"NVD metric was present but did not pass validation","not_found":"CVE not found in NVD",
        "not_requested":"NVD lookup not requested due to the bounded daily cap"}
    return states.get(record.get("cvss_status"),"CVSS not available / not applicable")

def enrich_kev_records(records,max_workers=8):
    """Follow vendor URLs supplied by CISA KEV for recent additions only."""
    tasks=[]
    for record in records:
        raw=str(record.get("notes") or "")
        urls=[u.rstrip(").,") for u in re.findall(r"https://[^\s,;<>]+",raw)]
        for url in urls[:2]:
            host=urlparse(url).netloc.lower()
            if not host or any(domain in host for domain in ("cisa.gov","nvd.nist.gov","cve.org","mitre.org")):continue
            tasks.append((record,url))
    if not tasks:return
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures={pool.submit(enrich_page,url):(record,url) for record,url in tasks}
        for future in as_completed(futures):
            record,url=futures[future]
            try:page=future.result()
            except Exception:page={"details":""}
            source_url=page.get("resolved_url") or url
            guidance=extract_specific_remediation(page.get("details",""))
            candidates=extract_candidate_fixed_releases(page.get("details",""),source_url)
            if guidance or candidates:
                record.setdefault("vendor_remediation",[]).append({
                    "source_url":source_url,"source_label":"CISA-linked vendor advisory",
                    "guidance":guidance[:4],"candidate_fixed_releases":candidates,
                    "confidence":"Concrete remediation wording extracted from a CISA-linked vendor reference; analyst review required"
                })


def attach_kev_remediation_evidence(records):
    """Build the KEV remediation evidence object after linked vendor pages are enriched."""
    for record in records:
        vendor_fixes=record.get("vendor_remediation",[])
        source_action=extract_specific_remediation(str(record.get("requiredAction") or ""))
        record["remediation_evidence"]=build_remediation_evidence(
            record,"",source_action,vendor_fixes,False,False
        )

def extract_iocs(s,source,url):
    """Extract normalized IOC candidates only near explicit IOC context."""
    found={}
    def add(value,kind,display=None):
        key=(kind,value)
        found[key]={"value":value,"type":kind,"defanged_value":display or value}
    for match in IOCCTX.finditer(s):
        window=s[max(0,match.start()-100):min(len(s),match.end()+450)]
        for candidate in IP.findall(window):
            try:
                address=ipaddress.ip_address(candidate)
                if address.version==4 and address.is_global:
                    add(str(address),"ipv4",str(address).replace(".","[.]"))
            except ValueError:
                pass
        for candidate in IPV6.findall(window):
            try:
                address=ipaddress.ip_address(candidate)
                if address.version==6 and address.is_global:
                    add(address.compressed,"ipv6")
            except ValueError:
                pass
        for candidate in DOMAIN.findall(window):
            domain=candidate.rstrip(".").lower()
            if not domain.endswith((".example",".test",".invalid",".localhost")):
                add(domain,"domain",domain.replace(".","[.]"))
        for candidate in HASH.findall(window):
            add(candidate.lower(),"hash")
        for candidate in URLIOC.findall(window):
            raw=candidate.rstrip(".,;)]}")
            parsed=urlparse(raw)
            if parsed.scheme.lower() not in {"http","https"} or not parsed.hostname or parsed.username or parsed.password:
                continue
            host=parsed.hostname.rstrip(".").lower()
            try:
                host_ip=ipaddress.ip_address(host)
                if not host_ip.is_global:
                    continue
            except ValueError:
                if "." not in host or host.endswith((".example",".test",".invalid",".localhost")):
                    continue
            try:
                port=parsed.port
            except ValueError:
                continue
            netloc=host
            if port:
                netloc+=":"+str(port)
            normalized=parsed._replace(scheme=parsed.scheme.lower(),netloc=netloc).geturl()
            display_scheme="hxxps" if parsed.scheme.lower()=="https" else "hxxp"
            display=display_scheme+"://"+host.replace(".","[.]")+((":"+str(port)) if port else "")+(parsed.path or "")+(("?"+parsed.query) if parsed.query else "")
            add(normalized,"url",display)
        for candidate in EMAILIOC.findall(window):
            local,domain=candidate.rsplit("@",1)
            domain=domain.lower().rstrip(".")
            if domain.endswith((".example",".test",".invalid",".localhost")):
                continue
            normalized=local+"@"+domain
            add(normalized,"email",local+"[@]"+domain.replace(".","[.]"))
        for candidate in FILENAMEIOC.findall(window):
            add(candidate.lower(),"filename")
    return [{**record,"source":source,"source_url":url,
             "confidence":"candidate near explicit IOC wording; verify against primary source"}
            for record in found.values()]

def main():
    health=[];errors=[];entries=[];business_entries=[];kev={};success=0;health_state=load_source_health_state()
    # ACSC is intentionally excluded after persistent upstream timeouts; remove its stale failure from health.
    health_state.pop("Australian ACSC",None)
    started=time.perf_counter()
    try:
        kev=json.loads(fetch(KEV).decode());success+=1
        health.append(record_source_health(health_state,"CISA KEV",KEV,"success",len(kev.get("vulnerabilities",[])),started))
    except Exception as e:
        errors.append(f"CISA KEV: {type(e).__name__}: {e}");health.append(record_source_health(health_state,"CISA KEV",KEV,"failed",0,started,e))
    for f in FEEDS:
        started=time.perf_counter()
        try:
            feed_raw=fetch(f[2])
            rows=parse_feed(feed_raw,f);entries+=rows;success+=1
            health.append(record_source_health(health_state,f[1],f[2],"success",len(rows),started))
        except Exception as e:
            errors.append(f"{f[1]}: {type(e).__name__}: {e}");health.append(record_source_health(health_state,f[1],f[2],"failed",0,started,e))
    for bid,bname,burl in BUSINESS_FEEDS:
        started=time.perf_counter()
        try:
            bf=(bid,bname,burl,"business","medium")
            rows=parse_feed(fetch(burl),bf);business_entries+=rows;success+=1
            health.append(record_source_health(health_state,bname,burl,"success",len(rows),started,stream="business"))
        except Exception as e:
            errors.append(f"{bname}: {type(e).__name__}: {e}");health.append(record_source_health(health_state,bname,burl,"failed",0,started,e,stream="business"))
    cert_url="https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST02&year="+str(NOW.year)
    started=time.perf_counter()
    try:
        p=CertParser();p.feed(fetch(cert_url).decode("utf-8",errors="replace"))
        for x in p.rows:entries.append({"source_id":"cert_in","source":"CERT-In India","source_type":"government","priority":"critical",
            "title":x["title"],"url":x["url"],"summary":"Official CERT-In index entry. Open advisory for technical details and remediation.",
            "published":None,"_date":None,"undated_certin":True})
        success+=1;health.append(record_source_health(health_state,"CERT-In India advisory index",cert_url,"success",len(p.rows),started,note="Index scrape; open advisory to confirm details"))
    except Exception as e:
        errors.append(f"CERT-In index: {type(e).__name__}: {e}");health.append(record_source_health(health_state,"CERT-In India advisory index",cert_url,"failed",0,started,e))
    save_source_health_state(health_state)
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
        companies=sorted({name for name in ("CrowdStrike","Zscaler","Palo Alto Networks","Microsoft","Google","Cisco","Fortinet","Check Point","SentinelOne","Mandiant","Broadcom","VMware","IBM","Amazon","Cloudflare","Okta","Proofpoint","Tenable","Rapid7","Wiz","Rubrik","Splunk","Akamai") if re.search(re.escape(name),body,re.I)},key=str.lower)
        event_key=("m&a:"+ "|".join(name.lower() for name in companies[:4])+":"+status.lower()) if category=="M&A" and len(companies)>=2 else category+":"+normalize_story_text(x["title"])
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
        # Fail-safe backfill: every CVE visible in the full text must also be indexed.
        evidence_cves=set(extract_cves(item.get("title"),item.get("summary"),item.get("details")))
        missing_cves=evidence_cves-set(item["cves"])
        if missing_cves:
            item["cves"]=sorted(set(item["cves"])|evidence_cves)
            item["cve_extraction_recovered"]=sorted(missing_cves)
        item["cve_count"]=len(item["cves"])
    for x in items:
        body=x.get("title","")+" "+x.get("summary","")+" "+x.get("details","")
        x["attack_techniques"]=sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b",body,re.I)))
    vulns=kev.get("vulnerabilities",[]) if kev else []
    recentkev=sorted([v for v in vulns if v.get("dateAdded","")>=(NOW_IST.date()-dt.timedelta(days=7)).isoformat()],key=lambda x:x.get("dateAdded",""),reverse=True)
    enrich_kev_records(recentkev[:40])
    attach_kev_remediation_evidence(recentkev[:40])
    epss_enrichment=enrich_epss(recentkev[:40]+items)
    cvss_enrichment=enrich_nvd_cvss(recentkev[:20])
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
        "errors":errors,"business_items":business_items,"business_feed_count":len(business_items),"business_window_hours":168,"cisa_kev_catalog_count":len(vulns),"cisa_kev_catalog":vulns,"cisa_kev_added_last_7_days":recentkev,"items":items,"epss_enrichment":epss_enrichment,"cvss_enrichment":cvss_enrichment,
        "ioc_candidates":iocs,"ioc_policy":"Candidate extraction only near explicit IOC wording. Verify against original report and local context.",
        "limitations":["Public feeds are not exhaustive and can fail or change format.","CERT-In is an official index scrape, not an RSS feed; open advisory pages to confirm details.",
        "Authenticated/paid feeds are not configured.","A CVE listing or IOC match is not proof of compromise.","No automatic response actions."]}
    (ROOT/snapshot).write_text(json.dumps(data,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    latest={"date_utc":DAY_UTC,"date_ist":DAY,"retrieved_at":STAMP,"retrieved_at_ist":STAMP_IST,"snapshot":f"snapshots/{DAY[:4]}/{DAY[5:7]}/{DAY[8:10]}.json","report":f"daily/{DAY[:4]}/{DAY[5:7]}/{DAY[8:10]}.md"}
    (ROOT/"intel/latest.json").write_text(json.dumps(latest,indent=2)+"\n",encoding="utf-8")
    lines=[f"# Global Cyber Threat Radar — Automated Snapshot — {DAY} IST","",f"- Retrieved: {STAMP_IST} (UTC: {STAMP})","- Coverage: last 72 hours + undated CERT-In index entries",
        f"- Feed health: {good}/{len(health)}",f"- Advisory/research items: {len(items)}",f"- CISA KEV catalog: {len(vulns)}",f"- KEV additions last 7 days: {len(recentkev)}",f"- IOC candidates: {len(iocs)}",
        "","## Feed health","","| Source | Status | Result | Records | Last successful collection (UTC) | Last attempt (UTC) | Duration (ms) | Consecutive failures |","|---|---|---|---:|---|---|---:|---:|"]
    lines += [f"| {x['source']} | {x['status']} | {x.get('collection_result','unknown')} | {x['records']} | {x.get('last_success_at') or 'never'} | {x.get('last_attempt_at','unknown')} | {x.get('duration_ms','unknown')} | {x.get('consecutive_failures',0)} |" for x in health]
    lines += ["","## CISA KEV additions — last 7 days",""]
    if recentkev:
        for v in recentkev[:40]:
            lines.append(f"- **{v.get('cveID','CVE unavailable')} — {v.get('vulnerabilityName','Name unavailable')}** | {v.get('vendorProject','unknown')} / {v.get('product','unknown')} | added {v.get('dateAdded','unknown')} | due {v.get('dueDate','not stated')} | [CISA record]({v.get('notes','https://www.cisa.gov/known-exploited-vulnerabilities-catalog')})")
            lines.append("  - Fix / remediation: "+kev_remediation_text(v))
            lines.append("  - EPSS context: "+format_epss_context(v)+" — FIRST.org; not an asset-specific risk score")
            lines.append("  - CVSS context: "+format_cvss_context(v)+" — NVD technical severity, not an asset-specific risk score")
            for ref in v.get("vendor_remediation",[]):
                lines.append("  - Vendor evidence: ["+str(ref.get("source_label") or "Vendor advisory")+"]("+str(ref.get("source_url") or "")+") — analyst review required")
    else:lines.append("- No additions returned, or the feed failed; check source health.")
    lines += ["","## Advisories, campaigns and research — last 72 hours",""]
    if items:
        for x in items[:100]:lines += [f"### {x['title']}",f"- Source: {x['source']} | Published: {x.get('published') or 'date not exposed in index'} | Detail enrichment: {x.get('enrichment_status','feed summary only')}",
            f"- CVEs: {', '.join(x['cves']) or 'none extracted'} | Topic signals: {', '.join(x['topics']) or 'analyst review required'}",
            f"- Summary: {x.get('summary','')[:900]}",
            f"- Technical details: {x.get('details') or x.get('summary','')[:900]}",
            f"- Fix / remediation: {x.get('remediation_guidance') or x.get('remediation_status') or 'Fix status unknown; check the linked vendor advisory for updates.'}",
            f"- EPSS context: {format_epss_context(x)} — FIRST.org; not an asset-specific risk score",
            f"- [Open source item]({x['url']})",""]
    else:lines.append("No dated items returned. This does not mean no threats occurred; inspect source health.")
    business_health=[x for x in health if x.get("stream")=="business"]
    business_ok=sum(x.get("status")=="success" for x in business_health)
    lines += ["","## Cyber business & market developments — last 7 days (newest first)",
        f"- Updated: {STAMP_IST} | Items collected: {len(business_items)} | Business feeds healthy: {business_ok}/{len(business_health)} | Window: 7 days"]
    failed_business=[x for x in business_health if x.get("status")!="success"]
    if failed_business:
        lines += ["- Feed issues: "+"; ".join(x["source"]+" — "+str(x.get("error") or "unavailable") for x in failed_business)]
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
