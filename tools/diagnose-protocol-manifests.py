"""Compare live Sonos manifest traversal using protocol roots only."""
import hashlib,json,re,tempfile,time,urllib.error,urllib.request
import xml.etree.ElementTree as ET
from collections import deque
from pathlib import Path
from urllib.parse import urljoin,urlsplit
from sonos_firmware.frontier import protocol_roots
from sonos_firmware.crawl import crawl_manifests
from sonos_firmware.discovery import USER_AGENT
from sonos_firmware.source_urls import open_sonos,sonos_url

roots=protocol_roots()
headers={'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:154.0) Gecko/20100101 Firefox/154.0',
         'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
         'Accept-Language':'en-US,en;q=0.9','Cache-Control':'no-cache','Connection':'close','Pragma':'no-cache'}
cache={};comparisons=[];requests=0;deadline=time.monotonic()+660

def retrieve(url,browser=True):
    global requests
    if not sonos_url(url) or not urlsplit(url).path.lower().endswith('.upm'):
        raise ValueError('metadata diagnostic fetches only Sonos manifest URLs')
    if time.monotonic()>=deadline:
        raise TimeoutError('diagnostic metadata budget reached')
    req=urllib.request.Request(url,headers=headers if browser else {'User-Agent':USER_AGENT})
    requests+=1
    with open_sonos(req,timeout=5) as response:
        if not urlsplit(response.url).path.lower().endswith('.upm'):
            raise ValueError('metadata diagnostic does not read redirected payload bodies')
        body=response.read(2_000_001)
        if len(body)>2_000_000:raise ValueError('manifest exceeds metadata bound')
        return body,response.url,response.headers.get('Content-Location')

def fetch(url):
    if url not in cache:
        try:cache[url]=retrieve(url)
        except Exception as error:
            cache[url]=error
    value=cache[url]
    if isinstance(value,Exception):raise value
    return value

paused=set()
for url in roots:
    if urlsplit(url).hostname in paused:continue
    for browser in (False,True):
        try:
            result=retrieve(url,browser)
            comparisons.append({'url':url,'headers':'browser' if browser else 'archive','http_status':200,'bytes':len(result[0])})
            if browser:cache[url]=result
        except Exception as error:
            comparisons.append({'url':url,'headers':'browser' if browser else 'archive',
                                'http_status':getattr(error,'code',None),'error':type(error).__name__})
            if getattr(error,'code',None)==429:
                paused.add(urlsplit(url).hostname);break
            if browser:cache[url]=error
print(json.dumps({'phase':'header-comparison','results':comparisons}),flush=True)

queue=deque(roots);seen=set();manifest_urls=set();installers=set();failures=[]
def enqueue(url,parent):
    url=urljoin(parent,url).replace('http://','https://',1)
    if not sonos_url(url) or not urlsplit(url).path.lower().endswith('.upm'):return
    if url not in seen:queue.append(url)
    for a,b in (('/Prod/','/Dev/'),('/Dev/','/Prod/')):
        if a in url:
            other=url.replace(a,b,1)
            if other not in seen:queue.append(other)
            break

while queue and len(seen)<80 and time.monotonic()<deadline:
    url=queue.popleft()
    if url in seen or urlsplit(url).hostname in paused:continue
    seen.add(url)
    try:
        body,resolved,location=fetch(url)
        canonical=urljoin(resolved,location) if location else resolved
        if not sonos_url(canonical):raise ValueError('non-Sonos manifest location')
        if canonical!=url:enqueue(canonical,url)
        text=body.decode('utf-8');end=text.find('</update_manifest>')
        if end<0:raise ValueError('no complete XML manifest')
        tree=ET.fromstring(text[:end+len('</update_manifest>')]);manifest_urls.add(canonical)
        links=[tree.get('base_url','')]+[(e.text or '').strip() for e in tree.iter() if e.tag.rsplit('}',1)[-1]=='image']
        for link in links:
            if not link.startswith(('http://','https://')):continue
            if urlsplit(link).path.lower().endswith(('.exe','.dmg')):installers.add(link.replace('http://','https://',1))
            if '^' in link:target=link.split('^',1)[0].rstrip('/')+'/update.upm'
            elif urlsplit(link).path.lower().endswith(('.exe','.dmg','.upd','.bin')):target=link.rsplit('/',1)[0]+'/update.upm'
            else:target=link
            enqueue(target,canonical)
    except Exception as error:
        failures.append({'url':url,'http_status':getattr(error,'code',None),'error':type(error).__name__})
        if getattr(error,'code',None)==429:paused.add(urlsplit(url).hostname)
    if len(seen)%10==0:print(json.dumps({'phase':'protocol-reference-traversal','visited':len(seen),'manifests':len(manifest_urls)}),flush=True)
    time.sleep(.1)

with tempfile.TemporaryDirectory() as temporary:
    production=crawl_manifests({},[{'url':u} for u in roots],[],Path(temporary),max_manifests=128,
        delay=0,fetch=fetch,explore_channels=True,deadline=deadline,paused_hosts=paused)
report={'roots':roots,'header_comparison':comparisons,'request_total':requests,
        'reference_traversal':{'manifest_urls':sorted(manifest_urls),'installer_urls':sorted(installers),
                               'failures':failures,'pending_urls':list(dict.fromkeys(queue))},
        'production_traversal':{'manifest_urls':sorted({x['url'] for x in production['manifests']}),
                               'installer_urls':sorted({x.url for x in production['candidates'] if urlsplit(x.url).path.lower().endswith(('.exe','.dmg'))}),
                               'failures':[{'url':x['url'],'kind':x['kind'],'http_status':x.get('status')} for x in production['failures']],
                               'pending_urls':production['pending_manifest_urls']}}
Path('protocol-manifest-diagnostic.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'phase':'complete','requests':requests,'reference_manifests':len(manifest_urls),
                 'reference_installers':len(installers),'production_manifests':len(report['production_traversal']['manifest_urls']),
                 'production_installers':len(report['production_traversal']['installer_urls'])}),flush=True)
