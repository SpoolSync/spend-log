#!/usr/bin/env python3
"""Open every Tally screen, sheet and dialog at three iPhone widths in light and dark mode and check:
   accessibility (axe: serious/critical), page wider than the screen, cut-off text, small tap targets, console errors.
   Then check the app still opens with no internet. Writes audit.json and prints a de-duplicated list."""
import json,sys
from playwright.sync_api import sync_playwright
U='http://localhost:8781/'
WIDTHS=[(320,568),(375,812),(430,932)]
SEED='''async()=>{
 await store.setCards([{id:"c1",name:"Example Visa",last4:"1234",kind:"credit"},{id:"c2",name:"Example Debit",last4:"5678",kind:"debit"}]);
 const t=new Date(),d=(o)=>{const x=new Date(t);x.setDate(x.getDate()-o);return x.toISOString().slice(0,10)};
 const E=[["Coffee","Cafe",4.35,"eating","want",1,"c1"],["Lunch","Diner",36.16,"eating","want",2,"c1"],["Gas","Gas station",62.10,"transport","need",4,"c2"],["Movie","Cinema",34.50,"fun","want",3,"c1"],["Headphones","Electronics store",149.99,"shopping","impulse",9,"c2"]];
 for(const e of E)await store.saveEntry({what:e[0],where:e[1],amount:e[2],category:e[3],why:e[4],date:d(e[5]),time:"12:30",pay:"Credit card",cardId:e[6]});
 await store.saveEntry({what:"Grocery run",where:"Grocery store",amount:40.15,category:"groceries",why:"need",date:d(6),cardId:"c1",items:[{id:"681131911080",name:"MILK POWDER",cost:11.97},{id:"059000016520",name:"FLOUR",cost:10.97}]});
 await store.setBudgets({eating:120,groceries:400});
}'''
CHECK=r'''()=>{
 const out={overflow:[],clipped:[],small:[]};
 const vw=innerWidth;
 if(document.documentElement.scrollWidth>vw+1)out.overflow.push('page '+document.documentElement.scrollWidth+'>'+vw);
 document.querySelectorAll('dialog[open]').forEach(d=>{if(d.scrollWidth>d.clientWidth+1)out.overflow.push('#'+d.id+' '+d.scrollWidth+'>'+d.clientWidth);});
 const vis=el=>{const r=el.getBoundingClientRect();const s=getComputedStyle(el);return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none'&&r.bottom>0&&r.top<innerHeight*3;};
 const top=document.querySelector('dialog[open]:last-of-type')||document;
 const scope=[...document.querySelectorAll('dialog[open]')].pop()||document.getElementById('app');
 scope.querySelectorAll('button,a,label,.chip,h1,h2,h3,.rname,.ramt,.mt,.ms,.qv span,.amt,.what,.catopt span,.payopt,.fsel,.lg span,.hpill,.status,.nb span').forEach(el=>{
   if(!vis(el))return;const s=getComputedStyle(el);
   if(s.textOverflow==='ellipsis')return;
   if(el.scrollWidth>el.clientWidth+2&&(s.overflow==='hidden'||s.overflowX==='hidden'||s.whiteSpace==='nowrap'))out.clipped.push(desc(el)+' '+el.scrollWidth+'>'+el.clientWidth);
   const r=el.getBoundingClientRect();if(r.right>vw+1)out.clipped.push(desc(el)+' runs off screen right '+Math.round(r.right)+'>'+vw);
 });
 scope.querySelectorAll('button,a[href],input:not([type=hidden]):not(.vh),select:not(.vh),summary,[role=radio],label.check').forEach(el=>{
   if(!vis(el)||el.closest('.vh'))return;if((el.type==='radio'||el.type==='checkbox')&&el.closest('label')&&el.closest('label').getBoundingClientRect().height>=32)return;const r=el.getBoundingClientRect();if(el.classList.contains('vh'))return;
   if((r.height<24||r.width<24))out.small.push(desc(el)+' '+Math.round(r.width)+'x'+Math.round(r.height));
 });
 function desc(el){return el.tagName.toLowerCase()+(el.id?'#'+el.id:'')+(el.className&&typeof el.className==='string'?'.'+el.className.split(' ').filter(Boolean).slice(0,2).join('.'):'')+' "'+(el.textContent||el.value||el.getAttribute('aria-label')||'').trim().slice(0,28)+'"';}
 return out;}'''
STATES=[]
def state(name):
    def deco(f):STATES.append((name,f));return f
    return deco
def closeAll(pg):pg.evaluate('document.querySelectorAll("dialog[open]").forEach(d=>d.close())');pg.wait_for_timeout(150)
for t in ["home","log","returns","more","bills","budgets","cards","inbox","import","settings","subs","warranty","report"]:
    (lambda t:state("tab:"+t)(lambda pg:(closeAll(pg),pg.evaluate('t=>{S.repMonth=ym(today());S.repFrom="home";go(t)}',t))))(t)
@state("purchases filtered")
def _(pg):closeAll(pg);pg.evaluate('S.f={cat:"eating"};go("log")')
@state("chooser")
def _(pg):closeAll(pg);pg.evaluate('openChooser(today())')
@state("new purchase sheet")
def _(pg):closeAll(pg);pg.evaluate('openEntry({date:today()});$("f-more").open=true')
@state("edit purchase sheet (items, card)")
def _(pg):closeAll(pg);pg.evaluate('openEntry(S.entries.find(e=>e.items&&e.items.length)||S.entries[0]);$("f-more").open=true')
@state("quick check")
def _(pg):
    closeAll(pg);pg.evaluate('''()=>{openEntry({date:today()});$("f-where").value="Walmart";$("f-what").value="GV Milk Pwdr, Flour +8 more";$("f-amount").value="59.50";$("f-cat").value="groceries";
      $("f-items").value="681131911080 | GV MILK PWDR | 12.97\\n059000016520 | FLOUR | 11.97";pendingReceipt={no:"1",time:"17:32",total:59.5};quickCheck({where:"Walmart",date:today(),verified:true,last4:"1234",items:[]});}''')
@state("card dialog")
def _(pg):closeAll(pg);pg.evaluate('openCard(null,"9999")')
@state("return dialog")
def _(pg):closeAll(pg);pg.evaluate('openReturn(S.entries.find(e=>e.items&&e.items.length)||S.entries[0],-1)')
@state("bill dialog")
def _(pg):closeAll(pg);pg.evaluate('openBill(S.bills[0]||null)')
def run(scheme,w,h,findings,axeSeen):
    with sync_playwright() as p:
        b=p.chromium.launch(executable_path='/usr/bin/google-chrome',args=['--no-sandbox']);errs=[]
        pg=b.new_page(viewport={'width':w,'height':h},device_scale_factor=2,color_scheme=scheme)
        pg.on('pageerror',lambda e:errs.append(str(e)[:200]));pg.on('console',lambda m:errs.append('console: '+m.text[:200]) if m.type=='error' else None)
        pg.goto(U);pg.wait_for_selector('#acct:not([hidden])')
        for nm in ['sign-in screen','lock screen']:
            if nm=='lock screen':pg.click('text=Use on this phone only');pg.wait_for_selector('#lock:not([hidden])')
            pg.add_script_tag(url='/axe.min.js') if nm=='sign-in screen' else None
            audit_state(pg,nm,scheme,w,findings,axeSeen)
        pg.fill('#l-pass','1234');pg.fill('#l-confirm','1234');pg.click('#l-go');pg.wait_for_selector('#navbar:not([hidden])',timeout=20000)
        pg.evaluate(SEED);pg.evaluate('store.saveBill({name:"Rent",amount:1850,dueDay:1,category:"housing"})');pg.wait_for_timeout(600)
        for nm,f in STATES:
            try:f(pg);pg.wait_for_timeout(350);audit_state(pg,nm,scheme,w,findings,axeSeen)
            except Exception as e:findings.append({"state":nm,"kind":"crash","what":str(e)[:200],"where":"%s %d"%(scheme,w)})
        for e in errs:findings.append({"state":"-","kind":"console","what":e,"where":"%s %d"%(scheme,w)})
        b.close()
def audit_state(pg,nm,scheme,w,findings,axeSeen):
    r=pg.evaluate(CHECK)
    for k in ("overflow","clipped","small"):
        for x in r[k]:findings.append({"state":nm,"kind":k,"what":x,"where":"%s %d"%(scheme,w)})
    ax=pg.evaluate('''async()=>{const r=await axe.run(document,{runOnly:{type:"tag",values:["wcag2a","wcag2aa","wcag21aa"]}});return r.violations.filter(v=>v.impact==="serious"||v.impact==="critical").map(v=>({id:v.id,help:v.help,nodes:v.nodes.slice(0,4).map(n=>n.target.join(" ")+" :: "+(n.failureSummary||"").split("\\n").slice(1,2).join("").slice(0,120))}))}''')
    for v in ax:
        for n in v["nodes"]:
            key=v["id"]+"|"+n.split(" :: ")[0]
            if key in axeSeen:continue
            axeSeen.add(key);findings.append({"state":nm,"kind":"axe:"+v["id"],"what":n,"where":"%s %d"%(scheme,w)})
def offline(findings):
    with sync_playwright() as p:
        b=p.chromium.launch(executable_path='/usr/bin/google-chrome',args=['--no-sandbox']);ctx=b.new_context(viewport={'width':390,'height':844});pg=ctx.new_page();errs=[]
        pg.on('pageerror',lambda e:errs.append(str(e)[:200]))
        pg.goto(U);pg.wait_for_selector('#acct:not([hidden])');pg.click('text=Use on this phone only');pg.fill('#l-pass','1234');pg.fill('#l-confirm','1234');pg.click('#l-go');pg.wait_for_selector('#navbar:not([hidden])',timeout=20000)
        pg.evaluate('store.saveEntry({what:"Offline test",amount:3,date:today()})');pg.wait_for_timeout(2500);pg.reload();pg.wait_for_timeout(2500)
        ctx.set_offline(True);pg.reload();pg.wait_for_timeout(3000)
        ok=pg.evaluate('!document.getElementById("lock").hidden||!document.getElementById("app").hidden')
        if pg.evaluate('!document.getElementById("lock").hidden'):pg.fill('#l-pass','1234');pg.click('#l-go');pg.wait_for_timeout(1500)
        rows=pg.evaluate('S.entries.map(e=>e.what)')
        print('offline start:',ok,'| entries offline:',rows)
        if not ok or 'Offline test' not in rows:findings.append({"state":"offline","kind":"offline","what":"app did not open offline","where":"390"})
        for e in errs:findings.append({"state":"offline","kind":"console","what":e,"where":"390"})
        b.close()
findings=[];axeSeen=set()
for scheme in ("light","dark"):
    for w,h in WIDTHS:run(scheme,w,h,findings,axeSeen);print('done',scheme,w,len(findings),flush=True)
offline(findings)
json.dump(findings,open('audit.json','w'),indent=1)
seen={}
for f in findings:
    k=(f["kind"],f["what"].split(" ")[0]+" "+(f["what"].split('"')[1] if '"' in f["what"] else ""))
    seen.setdefault(k,[]).append(f)
print("\n%d findings, %d distinct"%(len(findings),len(seen)))
for k,v in sorted(seen.items()):
    print("- [%s] %s  | e.g. %s @ %s (%d×)"%(k[0],v[0]["what"][:150],v[0]["state"],v[0]["where"],len(v)))
