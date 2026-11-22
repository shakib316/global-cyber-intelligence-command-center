#!/usr/bin/env python3
"""Multi-source public cyber-intelligence collector. No automated response actions."""
import datetime as dt, email.utils, html, ipaddress, json, re, sys, urllib.request
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin

ROOT=Path(__file__).resolve().parents[1]
NOW=dt.datetime.now(dt.timezone.utc); DAY=NOW.date().isoformat(); STAMP=NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
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
("google_ti","Google Threat Intelligence / Mandiant","https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v","research","critical")]
CVE=re.compile(r"\bCVE-\d{4}-\d{4,8}\b",re.I)
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
        if title or link:
            out.append({"source_id":f[0],"source":f[1],"source_type":f[3],"priority":f[4],
                "title":html.unescape(re.sub(r"<[^>]+>"," ",title)).strip(),
                "url":urljoin(f[2],html.unescape(link.strip())),
                "summary":html.unescape(re.sub(r"<[^>]+>"," ",summary)).strip()[:4000],
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
    health=[];errors=[];entries=[];kev={};success=0
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
    cert_url="https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST02&year="+str(NOW.year)
    try:
        p=CertParser();p.feed(fetch(cert_url).decode("utf-8",errors="replace"))
        for x in p.rows:entries.append({"source_id":"cert_in","source":"CERT-In India","source_type":"government","priority":"critical",
            "title":x["title"],"url":x["url"],"summary":"Official CERT-In index entry. Open advisory for technical details and remediation.",
            "published":None,"_date":None,"undated_certin":True})
        success+=1;health.append({"source":"CERT-In India advisory index","status":"success","records":len(p.rows),"url":cert_url,"note":"Index scrape; open advisory to confirm details"})
    except Exception as e:
        errors.append(f"CERT-In index: {type(e).__name__}: {e}");health.append({"source":"CERT-In India advisory index","status":"failed","records":0,"url":cert_url,"error":str(e)})
    cutoff=NOW-dt.timedelta(hours=72);selected=[]
    for x in entries:
        body=x["title"]+" "+x["summary"];x["cves"]=sorted({v.upper() for v in CVE.findall(body)});x["topics"]=topics(body)
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
    vulns=kev.get("vulnerabilities",[]) if kev else []
    recentkev=sorted([v for v in vulns if v.get("dateAdded","")>=(NOW.date()-dt.timedelta(days=7)).isoformat()],key=lambda x:x.get("dateAdded",""),reverse=True)
    iocmap={}
    for x in items:
        for v in extract_iocs(x["title"]+" "+x["summary"],x["source"],x["url"]):iocmap[(v["type"],v["value"])]=v
    iocs=list(iocmap.values())
    if not success:print("All feeds failed; refusing to publish.");print("\n".join(errors));return 1
    good=sum(x["status"]=="success" for x in health)
    report=Path("intel/daily")/DAY[:4]/DAY[5:7]/(DAY[8:10]+".md")
    snapshot=Path("intel/snapshots")/DAY[:4]/DAY[5:7]/(DAY[8:10]+".json")
    (ROOT/report).parent.mkdir(parents=True,exist_ok=True);(ROOT/snapshot).parent.mkdir(parents=True,exist_ok=True)
    data={"date_utc":DAY,"retrieved_at":STAMP,"window_hours":72,"source_health":health,"successful_sources":good,"total_sources":len(health),
        "errors":errors,"cisa_kev_catalog_count":len(vulns),"cisa_kev_added_last_7_days":recentkev,"items":items,
        "ioc_candidates":iocs,"ioc_policy":"Candidate extraction only near explicit IOC wording. Verify against original report and local context.",
        "limitations":["Public feeds are not exhaustive and can fail or change format.","CERT-In is an official index scrape, not an RSS feed; open advisory pages to confirm details.",
        "Authenticated/paid feeds are not configured.","A CVE listing or IOC match is not proof of compromise.","No automatic response actions."]}
    (ROOT/snapshot).write_text(json.dumps(data,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    latest={"date_utc":DAY,"retrieved_at":STAMP,"snapshot":f"snapshots/{DAY[:4]}/{DAY[5:7]}/{DAY[8:10]}.json","report":f"daily/{DAY[:4]}/{DAY[5:7]}/{DAY[8:10]}.md"}
    (ROOT/"intel/latest.json").write_text(json.dumps(latest,indent=2)+"\n",encoding="utf-8")
    lines=[f"# Global Cyber Threat Radar — Automated Snapshot — {DAY} UTC","",f"- Retrieved: {STAMP}","- Coverage: last 72 hours + undated CERT-In index entries",
        f"- Feed health: {good}/{len(health)}",f"- Advisory/research items: {len(items)}",f"- CISA KEV catalog: {len(vulns)}",f"- KEV additions last 7 days: {len(recentkev)}",f"- IOC candidates: {len(iocs)}",
        "","## Feed health","","| Source | Status | Records |","|---|---|---:|"]
    lines += [f"| {x['source']} | {x['status']} | {x['records']} |" for x in health]
    lines += ["","## CISA KEV additions — last 7 days",""]
    if recentkev:
        for v in recentkev[:40]:lines.append(f"- **{v.get('cveID','CVE unavailable')} — {v.get('vulnerabilityName','Name unavailable')}** | {v.get('vendorProject','unknown')} / {v.get('product','unknown')} | added {v.get('dateAdded','unknown')} | due {v.get('dueDate','not stated')} | [CISA record]({v.get('notes','https://www.cisa.gov/known-exploited-vulnerabilities-catalog')})")
    else:lines.append("- No additions returned, or the feed failed; check source health.")
    lines += ["","## Advisories, campaigns and research — last 72 hours",""]
    if items:
        for x in items[:100]:lines += [f"### {x['title']}",f"- Source: {x['source']} | Published: {x.get('published') or 'date not exposed in index'}",
            f"- CVEs: {', '.join(x['cves']) or 'none extracted'} | Topic signals: {', '.join(x['topics']) or 'analyst review required'}",
            f"- {x['summary'][:400]}",f"- [Open source item]({x['url']})",""]
    else:lines.append("No dated items returned. This does not mean no threats occurred; inspect source health.")
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
        "- Feed failures and quiet periods do not mean absence of threats; timestamps are UTC.",
        "",f"Raw evidence: [JSON snapshot](../../../snapshots/{DAY[:4]}/{DAY[5:7]}/{DAY[8:10]}.json)."]
    (ROOT/report).write_text("\n".join(lines)+"\n",encoding="utf-8")
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
