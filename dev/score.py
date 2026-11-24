# Score the scanner on the test set: each photo goes through the app's own path (shrink, then read and parse)
import json,sys,time
from playwright.sync_api import sync_playwright
import os
T=json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),'receipts','truth.json')))
only=sys.argv[1:]
FIELDS=["where","amount","date","time","items","last4"]
def norm(s):return "".join(ch for ch in str(s or "").lower() if ch.isalnum())
res={};tot={f:0 for f in FIELDS};n=0;times=[]
with sync_playwright() as p:
    b=p.chromium.launch(executable_path='/usr/bin/google-chrome',args=['--no-sandbox']);pg=b.new_page();pg.goto('http://localhost:8781/');pg.wait_for_timeout(1500)
    pg.evaluate('reader()');pg.wait_for_timeout(3000)
    for name,tr in T.items():
        if only and not any(o in name for o in only):continue
        url='rx/corpus/'+name if not name.startswith('../') else 'rx/'+name[3:]
        t0=time.time()
        r=pg.evaluate('''async(u)=>{try{const blob=await fetch(u).then(r=>r.blob());const s=await shrink(new File([blob],"x.jpg",{type:blob.type}));return await readReceipt(s);}catch(e){return {err:String(e&&e.code||e)}}}''',url)
        dt=time.time()-t0;times.append(dt);n+=1
        got={"where":r.get("where"),"amount":r.get("amount"),"date":r.get("date"),"time":r.get("time"),"items":len([i for i in (r.get("items") or []) if (i.get("cost") or 0)>0]),"last4":r.get("last4") or ""}
        ok={"where":norm(got["where"])==norm(tr["where"]) or (norm(tr["where"]) and norm(tr["where"]) in norm(got["where"])),
            "amount":got["amount"] is not None and abs(float(got["amount"])-tr["amount"])<0.005,
            "date":got["date"]==tr["date"],"time":got["time"]==tr["time"],"items":got["items"]==tr["items"],"last4":(got["last4"] or "")==tr["last4"]}
        for f in FIELDS:tot[f]+=ok[f]
        bad=[f+"="+repr(got[f])+"≠"+repr(tr[f]) for f in FIELDS if not ok[f]]
        print("%-22s %5.1fs %s %s"%(name.replace('../',''),dt,"OK " if not bad else "   ",("; ".join(bad))+(" ERR "+r["err"] if r.get("err") else "")))
    b.close()
print("\nSCORE  "+"  ".join("%s %d/%d"%(f,tot[f],n) for f in FIELDS)+"   all-fields %d/%d"%(sum(tot.values()),n*len(FIELDS))+"   avg %.1fs"%(sum(times)/max(1,len(times))))
