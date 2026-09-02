from __future__ import annotations
from collections import deque
from urllib.parse import urlparse
from core.module import ExploitModule
from core.models import Artifact, ExploitResult

class ReconModule(ExploitModule):
    name='Recon / Browser-aware Discovery'; category='recon'
    async def run(self,ctx):
        scope=urlparse(ctx.target.url).netloc; seeds=[]
        if ctx.session.current_url: seeds.append(ctx.session.current_url)
        seeds += ctx.session.navigation_history
        seeds += [x.get('url','') for x in ctx.session.network_requests]
        seeds += [x.get('url','') for x in ctx.session.network_responses]
        seeds=ctx.normalize_urls(seeds,scope) or [ctx.target.url]
        endpoints=set(seeds); pages=set(); forms=[]; queue=deque(seeds[:40]); evidence=[]
        while queue and len(pages)<50:
            url=queue.popleft()
            if url in pages: continue
            pages.add(url)
            try:
                if url==ctx.session.current_url and ctx.session.page_html: text,final,status=ctx.session.page_html,url,200
                else: text,final,status=await ctx.get_text(url)
                ctx.inspect_source(final, text, payload="PASSIVE-CTRL-U", payload_index=0, content_type="text/html")
                evidence.append(f'{final} -> {status}')
                if status>=500: continue
                for link in ctx.discover_links(final,text):
                    if ctx.in_scope(link):
                        endpoints.add(link)
                        if link not in pages and len(queue)<80: queue.append(link)
                fs=ctx.discover_forms(final,text); forms.extend(fs); endpoints.update(f['action'] for f in fs)
                csrf=ctx.discover_csrf(text)
                if csrf: ctx.artifacts.set('csrf.tokens',[{'name':n,'value':v} for n,v in csrf])
            except Exception as exc: evidence.append(f'{url} -> error: {exc}')
        uniq=[]; seen=set()
        for f in forms:
            k=(f['method'],f['action'],tuple((x.get('name'),x.get('type')) for x in f['inputs']))
            if k not in seen: seen.add(k); uniq.append(f)
        endpoints=sorted(endpoints); pages=sorted(pages)
        ctx.artifacts.set('recon.endpoints',endpoints); ctx.artifacts.set('recon.forms',uniq); ctx.artifacts.set('recon.pages_seen',pages); ctx.artifacts.set('recon.browser_seed',seeds)
        request_corpus=ctx.request_corpus()
        methods=sorted({str(r.get('method') or 'GET').upper() for r in request_corpus}) or ['GET']
        ctx.artifacts.set('recon.requests',request_corpus); ctx.artifacts.set('recon.methods',methods)
        ctx.logger('[recon] HTTP methods observed/discovered: ' + ', '.join(methods))
        upload_forms = []
        for form in uniq:
            input_types = {str(x.get('type', '')).lower() for x in form.get('inputs', [])}
            input_names = {str(x.get('name', '')).lower() for x in form.get('inputs', [])}
            action = str(form.get('action', '')).lower()
            if 'file' in input_types or 'upload' in action or any('upload' in name or 'file' in name for name in input_names):
                upload_forms.append(form)
        if upload_forms:
            ctx.artifacts.set('recon.upload_endpoints', [f.get('action') for f in upload_forms])
        return ExploitResult(self.name,'ok',f'Discovered {len(endpoints)} endpoint(s), {len(uniq)} form(s), {len(pages)} page(s)',[Artifact('recon.endpoints',endpoints,self.name),Artifact('recon.forms',uniq,self.name),Artifact('recon.pages_seen',pages,self.name),Artifact('recon.requests',request_corpus,self.name),Artifact('recon.methods',methods,self.name)],'\n'.join(evidence[:35]))
