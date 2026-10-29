#!/usr/bin/env python3
"""Conservative ET Open UDP C2 preview. No firewall changes or automatic import."""
import argparse
import gzip
import ipaddress
import pathlib
import re
import sys
import tarfile
import urllib.request

SOURCE = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz"
FILES = {"emerging-botcc.rules", "emerging-botcc.portgrouped.rules",
         "emerging-malware.rules", "emerging-trojan.rules", "emerging-current_events.rules"}
HEADER = re.compile(r'^\s*alert\s+udp\s+(?:any|\$HOME_NET)\s+any\s+->\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,5})\s*\((.*)\)\s*$', re.I)
MESSAGE = re.compile(r'msg\s*:\s*"([^"]+)"', re.I)
DANGEROUS_OPTIONS = re.compile(
    r'\b(?:content|pcre|flow|flowbits|xbits|byte_test|byte_jump|dsize|'
    r'detection_filter|threshold|within|distance|offset|depth|startswith|endswith|'
    r'iprep|dataset|lua|file_data|pkt_data|base64_decode|base64_data|'
    r'http_[a-z_]+|dns_[a-z_]+|tls_[a-z_]+)\s*:', re.I)
# Any unknown options are excluded; only purely endpoint IOC rules are eligible.
ALLOWED_OPTION = re.compile(r'^(?:msg|sid|rev|classtype|reference|metadata|priority|gid)\s*:', re.I)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--archive",help="Local ET tar.gz (test/offline mode)")
    ap.add_argument("--output",help="Write candidate CSV here; never updates nftables")
    args=ap.parse_args()
    if args.archive:
        source=pathlib.Path(args.archive)
    else:
        print("Downloading ET Open rules for offline candidate review...",flush=True)
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".tar.gz",delete=False) as temp:
            source=pathlib.Path(temp.name)
        try:
            req=urllib.request.Request(SOURCE,headers={"User-Agent":"xtls-udp-etopen-preview/1.0"})
            with urllib.request.urlopen(req,timeout=45) as response, source.open("wb") as out:
                size=0
                while True:
                    chunk=response.read(65536)
                    if not chunk:break
                    size+=len(chunk)
                    if size>80_000_000:raise ValueError("Archive too large")
                    out.write(chunk)
            return scan(source,args.output)
        finally:
            source.unlink(missing_ok=True)
    return scan(source,args.output)

def scan(source,output):
    candidates={}
    scanned=0
    matching_files=0
    with tarfile.open(source,"r:gz") as archive:
        for member in archive:
            if not member.isfile() or pathlib.PurePosixPath(member.name).name not in FILES:
                continue
            matching_files+=1
            stream=archive.extractfile(member)
            if stream is None:continue
            for raw in stream:
                scanned+=1
                line=raw.decode("utf-8","replace").strip()
                if line.startswith("#") or not line.startswith("alert udp "):continue
                m=HEADER.match(line)
                if not m:continue
                address,port,opts=m.groups()
                try:
                    ip=ipaddress.IPv4Address(address); p=int(port)
                    if not ip.is_global or not 1<=p<=65535:continue
                except ValueError:continue
                if DANGEROUS_OPTIONS.search(opts):continue
                fields=[x.strip() for x in opts.strip(" ;").split(";") if x.strip()]
                if not fields or any(not ALLOWED_OPTION.match(x) for x in fields):continue
                msg=MESSAGE.search(opts)
                if not msg:continue
                title=msg.group(1)
                if not re.search(r'\b(?:CNC|C2|C&C|command.and.control)\b',title,re.I):continue
                if not re.search(r'\b(?:ET\s+(?:MALWARE|TROJAN|CNC)|BOTCC)\b',title,re.I):continue
                candidates[(str(ip),p)]=title
    print(f"Scanned rule lines: {scanned}; matching categories: {matching_files}")
    print(f"Conservative UDP endpoint candidates: {len(candidates)}")
    for (ip,port),title in list(sorted(candidates.items()))[:20]:
        print(f"  {ip}:{port}  {title}")
    if output:
        path=pathlib.Path(output)
        path.write_text("# Candidate-only: manually review before importing as confirmed\n"+
                        "".join(f"{ip},{port},udp\n" for ip,port in sorted(candidates)))
        print(f"Candidate file: {path} (NOT installed or activated)")
    return 0 if matching_files else 2

if __name__=="__main__":
    try:sys.exit(main())
    except Exception as exc:
        print(f"ET Open preview failed: {exc}",file=sys.stderr)
        sys.exit(1)
