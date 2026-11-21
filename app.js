"use strict";
var CATS=[["groceries","Groceries"],["eating","Eating out"],["transport","Transport & gas"],["housing","Rent & utilities"],["subs","Subscriptions"],["shopping","Shopping"],["health","Health"],["fun","Fun"],["work","Work & business"],["other","Other"]];
var CATNAME={};CATS.forEach(function(c){CATNAME[c[0]]=c[1];});
var WHYNAME={need:"Need",want:"Want",impulse:"Impulse"};
var PAYS=["Debit","Credit card","Cash","E-transfer","Other"];
var LOCAL_KEY="spendlog.v1";

var S={ready:false,mode:"connecting",stale:false,entries:[],bills:[],days:{},tab:"log",month:"",importText:"",importFlip:false,importPreview:null,importing:false};
var DEK=null,hiddenAt=0,canReadImages=true;
var pendingItems=null,pendingReceipt=null,dupOk=false,editing=null,pendingBlob=null,pendingType=null,previewUrl=null,deleteArmed=false,billEditing=null,billDeleteArmed=false,readCtl=null;

/* ---------- helpers ---------- */
function $(id){return document.getElementById(id);}
function h(tag,attrs){
  var el=document.createElement(tag),k,v;
  if(attrs)for(k in attrs){v=attrs[k];if(v==null||v===false)continue;
    if(k==="class")el.className=v;else if(k==="text")el.textContent=v;
    else if(k.slice(0,2)==="on")el.addEventListener(k.slice(2),v);
    else if(k==="style")el.style.cssText=v;else el.setAttribute(k,v===true?"":v);}
  for(var i=2;i<arguments.length;i++)add(el,arguments[i]);
  return el;
}
function add(el,c){if(c==null||c===false)return;if(Array.isArray(c)){c.forEach(function(x){add(el,x);});return;}el.append(c.nodeType?c:document.createTextNode(String(c)));}
function z(n){return String(n).padStart(2,"0");}
function iso(d){return d.getFullYear()+"-"+z(d.getMonth()+1)+"-"+z(d.getDate());}
function fromIso(s){var p=s.split("-");return new Date(+p[0],+p[1]-1,+p[2]);}
function today(){return iso(new Date());}
function ym(s){return s.slice(0,7);}
var fmt=new Intl.NumberFormat("en-CA",{style:"currency",currency:"CAD"});
function money(n){return fmt.format(Math.round((n||0)*100)/100).replace("CA","");}
function sum(a){return a.reduce(function(t,e){return t+net(e);},0);}
function monthLabel(m){var p=m.split("-");return new Date(+p[0],+p[1]-1,1).toLocaleDateString("en-CA",{month:"long",year:"numeric"});}
function shiftMonth(m,by){var p=m.split("-");var d=new Date(+p[0],+p[1]-1+by,1);return d.getFullYear()+"-"+z(d.getMonth()+1);}
function dayLabel(s){return fromIso(s).toLocaleDateString("en-CA",{weekday:"short",month:"short",day:"numeric"});}
function rid(){return Date.now().toString(36)+Math.random().toString(36).slice(2,8);}
function clean(o){return JSON.parse(JSON.stringify(o));}
var toastTimer=null;
function toast(msg){var t=$("toast");t.textContent=msg;t.hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(function(){t.hidden=true;},4000);}
function sortEntries(a){a.sort(function(x,y){return (y.date||"").localeCompare(x.date||"")||(y.time||"").localeCompare(x.time||"")||((y.createdAt||0)-(x.createdAt||0));});return a;}
function title(e){return e.what||e.where||e.bankDesc||"Purchase";}
function receiptMissing(e){return !e.receiptId&&!e.noReceipt;}
function covered(d){return !!(S.days[d]&&S.days[d].noSpend)||S.entries.some(function(e){return e.date===d;});}

/* ---------- encrypted storage (this phone only) ---------- */
var ITER=600000,dbp=null,writeChain=Promise.resolve();
function idbOpen(){
  if(!dbp)dbp=new Promise(function(res,rej){
    var r=indexedDB.open("spendlog",1);
    r.onupgradeneeded=function(){r.result.createObjectStore("kv");r.result.createObjectStore("receipts");};
    r.onsuccess=function(){res(r.result);};r.onerror=function(){rej(r.error);};
  });
  return dbp;
}
function idb(store,mode,fn){
  return idbOpen().then(function(db){return new Promise(function(res,rej){
    var tx=db.transaction(store,mode),rq=fn(tx.objectStore(store));
    tx.oncomplete=function(){res(rq?rq.result:undefined);};
    tx.onerror=tx.onabort=function(){rej(tx.error);};
  });});
}
function kvGet(k){return idb("kv","readonly",function(s){return s.get(k);});}
function kvSet(k,v){return idb("kv","readwrite",function(s){return s.put(v,k);});}
function recGet(k){return idb("receipts","readonly",function(s){return s.get(k);});}
function recSet(k,v){return idb("receipts","readwrite",function(s){return s.put(v,k);});}
function recDel(k){return idb("receipts","readwrite",function(s){return s.delete(k);});}
function recKeys(){return idb("receipts","readonly",function(s){return s.getAllKeys();});}
function wipeAll(){return idb("kv","readwrite",function(s){return s.clear();}).then(function(){return idb("receipts","readwrite",function(s){return s.clear();});});}

function rnd(n){return crypto.getRandomValues(new Uint8Array(n));}
async function kek(pass,salt,iter){
  var base=await crypto.subtle.importKey("raw",new TextEncoder().encode(pass),"PBKDF2",false,["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2",salt:salt,iterations:iter,hash:"SHA-256"},base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
async function seal(key,bytes){var iv=rnd(12);return {iv:iv,ct:new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:iv},key,bytes))};}
async function unseal(key,box){return new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:box.iv},key,box.ct));}
function importDek(raw){return crypto.subtle.importKey("raw",raw,"AES-GCM",false,["encrypt","decrypt"]);}

async function createVault(pass){
  var salt=rnd(16),raw=rnd(32),k=await kek(pass,salt,ITER);
  await kvSet("meta",{v:1,vid:rid(),mts:Date.now(),salt:salt,iter:ITER,wrapped:await seal(k,raw)});
  DEK=await importDek(raw);raw.fill(0);
  S.entries=[];S.bills=[];S.days={};S.daysTs=0;S.tomb={};S.seen={};
  await persist();
}
async function openVault(pass){
  var meta=await kvGet("meta"),k=await kek(pass,meta.salt,meta.iter);
  var raw=await unseal(k,meta.wrapped); /* throws when the passcode is wrong */
  var key=await importDek(raw);raw.fill(0);
  var box=await kvGet("state"),data={};
  if(box)data=JSON.parse(new TextDecoder().decode(await unseal(key,box)));
  DEK=key;S.entries=sortEntries(data.entries||[]);S.bills=data.bills||[];S.days=data.days||{};S.daysTs=data.daysTs||0;S.tomb=data.tomb||{};S.seen=data.seen||{};
}
async function changePass(cur,next){
  var meta=await kvGet("meta"),raw=await unseal(await kek(cur,meta.salt,meta.iter),meta.wrapped);
  var salt=rnd(16),k=await kek(next,salt,ITER);
  await kvSet("meta",{v:1,vid:meta.vid||rid(),mts:Date.now(),salt:salt,iter:ITER,wrapped:await seal(k,raw)});raw.fill(0);
  cloudMetaPush().catch(function(){});
}
function persist(){
  var snap=JSON.stringify({entries:S.entries,bills:S.bills,days:S.days,daysTs:S.daysTs||0,tomb:S.tomb||{},seen:S.seen||{}}),key=DEK;
  writeChain=writeChain.catch(function(){}).then(async function(){
    await kvSet("state",await seal(key,new TextEncoder().encode(snap)));
    cloudKick();dashKick();
  });
  return writeChain;
}

/* Anonymous feature counts (pixora-usage.js): a fixed word per feature, never amounts, names or receipts. */
var lastTab="";
function T(f){try{if(window.PixoraUsage)PixoraUsage.track(f);}catch(e){}}
var store={
  saveEntry:async function(e){
    var body=clean(e),id=e.id||rid();body.id=id;body.ts=Date.now();
    var i=S.entries.findIndex(function(x){return x.id===id;});
    if(i>=0)S.entries[i]=body;else S.entries.push(body);
    sortEntries(S.entries);await persist();render();return id;
  },
  deleteEntry:async function(id){(S.tomb=S.tomb||{})["e_"+id]=Date.now();S.entries=S.entries.filter(function(x){return x.id!==id;});await persist();render();},
  saveBill:async function(b){
    var body=clean(b),id=b.id||rid();body.id=id;body.ts=Date.now();
    var i=S.bills.findIndex(function(x){return x.id===id;});
    if(i>=0)S.bills[i]=body;else S.bills.push(body);
    await persist();render();
  },
  deleteBill:async function(id){(S.tomb=S.tomb||{})["b_"+id]=Date.now();S.bills=S.bills.filter(function(x){return x.id!==id;});await persist();render();},
  setNoSpend:async function(date,on){S.daysTs=Date.now();if(on)S.days[date]={noSpend:true};else delete S.days[date];await persist();render();}
};
function saveErr(e){
  if(e&&e.name==="QuotaExceededError")return "This phone has no room left for the app. Free up storage, then try again.";
  return "Couldn't save on this phone. Try again.";
}

/* ---------- on-phone stand-ins for cloud storage and receipt reading ---------- */
var assets={
  upload:async function(blob){
    var box=await seal(DEK,new Uint8Array(await blob.arrayBuffer())),id=rid();
    await recSet(id,{iv:box.iv,ct:box.ct,type:blob.type||"image/jpeg"});return {id:id};
  },
  delete:function(id){return recDel(id);}
};
var sample={json:function(prompt,opts){return readReceipt(opts.images[0]);}};

var receiptUrls=[];
async function recUrl(id){
  var rec=await recGet(id);if(!rec||!DEK)throw new Error("missing");
  var u=URL.createObjectURL(new Blob([await unseal(DEK,rec)],{type:rec.type||"image/jpeg"}));receiptUrls.push(u);return u;
}
function closeReceipt(){
  if($("receiptDlg").open)$("receiptDlg").close();
  receiptUrls.forEach(function(u){URL.revokeObjectURL(u);});receiptUrls=[];
  $("receiptImg").removeAttribute("src");$("receiptImg2").removeAttribute("src");
}
async function showReceipt(id,id2){
  closeReceipt();
  try{
    var i1=$("receiptImg"),i2=$("receiptImg2");i1.classList.remove("zoom");i2.classList.remove("zoom");
    i1.src=await recUrl(id);i2.hidden=!id2;
    if(id2){try{i2.src=await recUrl(id2);}catch(e){i2.hidden=true;}}
    $("receiptDlg").showModal();
  }catch(e){toast("This receipt photo is on the phone that scanned it. Photos stay on that phone; a full backup file brings them to this one.");}
}

/* Receipt reading runs on the phone, in a separate hidden frame (ocr.html), using the open-source
   PaddleOCR models through ONNX Runtime. The photo never leaves the device. */
var readerFrame=null,readerReady=null,readJobs={},readSeq=0;
addEventListener("message",function(ev){
  if(ev.origin!==location.origin||!readerFrame||ev.source!==readerFrame.contentWindow)return;
  var d=ev.data;
  if(d&&d.kind==="read-done"&&readJobs[d.id]){var j=readJobs[d.id];delete readJobs[d.id];if(d.error)j.rej({code:"upstream_error"});else j.res(d.boxes);}
});
function reader(){
  if(!readerReady)readerReady=new Promise(function(res,rej){
    var f=document.createElement("iframe");f.src="ocr.html";f.hidden=true;f.title="Receipt text reader";f.setAttribute("aria-hidden","true");
    var t=setTimeout(function(){readerReady=null;f.remove();readerFrame=null;rej({code:"upstream_error"});},180000);
    addEventListener("message",function on(ev){
      if(ev.origin===location.origin&&ev.source===f.contentWindow&&ev.data&&ev.data.kind==="reader-ready"){clearTimeout(t);removeEventListener("message",on);res(f);}
    });
    readerFrame=f;document.body.append(f);
  });
  return readerReady;
}
async function sizeForReading(blob){
  try{
    var bmp=await createImageBitmap(blob),s=Math.min(1,2000/Math.max(bmp.width,bmp.height));
    if(s===1)return blob;
    var c=document.createElement("canvas");c.width=Math.round(bmp.width*s);c.height=Math.round(bmp.height*s);
    c.getContext("2d").drawImage(bmp,0,0,c.width,c.height);
    return (await new Promise(function(res){c.toBlob(res,"image/jpeg",0.92);}))||blob;
  }catch(e){return blob;}
}
async function readReceipt(blob){
  var f=await reader(),small=await sizeForReading(blob);
  var boxes=await new Promise(function(res,rej){var id=++readSeq;readJobs[id]={res:res,rej:rej};f.contentWindow.postMessage({kind:"read",id:id,blob:small},location.origin);});
  var out=parseReceiptBoxes(boxes);
  if(!out)throw {code:"image_rejected"};
  return out;
}
var STORES=[["costco","Costco"],["walmart","Walmart"],["best buy","Best Buy"],["canadian tire","Canadian Tire"],["home depot","Home Depot"],["ikea","IKEA"],["winners","Winners"],["marshalls","Marshalls"],["homesense","HomeSense"],["shoppers","Shoppers Drug Mart"],["sport chek","Sport Chek"],["staples","Staples"],["dollarama","Dollarama"],["no frills","No Frills"],["loblaws","Loblaws"],["freshco","FreshCo"],["sobeys","Sobeys"],["food basics","Food Basics"],["tim hortons","Tim Hortons"],["mcdonald","McDonald's"],["starbucks","Starbucks"],["lcbo","LCBO"],["petro-canada","Petro-Canada"],["metro","Metro"]];
var PRICE_END=/\$?(\d{1,4}[.,]\d{2})\s*(-?)\s*[A-Z0-9 ]{0,5}$/;
var NOT_ITEM=/member|invoice|auth|reference|seq#|app#|approved|balance|amount|total|\btax\b|change|card|purchase|copy|records|items|\b(ave|avenue|st|street|rd|road|blvd|drive|hwy|unit|suite)\b/i;
function fixName(s){return s.replace(/\b0(?=[A-Z]{2})/g,"O").replace(/([A-Z])0(?=[A-Z])/g,"$1O").replace(/\s+/g," ").trim().slice(0,60);}
function parseReceiptBoxes(boxes){
  var lines=(boxes||[]).slice().sort(function(a,b){return a.y-b.y;}).map(function(b){return String(b.t||"").replace(/[：]/g,":").replace(/\s+/g," ").trim();}).filter(Boolean);
  var text=lines.join("\n");
  if(text.replace(/[^A-Za-z0-9]/g,"").length<12)return null;
  var low=text.toLowerCase(),out={where:"",what:"",amount:null,date:null,time:null,category:"",pay:null,receipt_no:null,items:[],verified:false},i,m;
  for(i=0;i<STORES.length;i++)if(low.indexOf(STORES[i][0])>=0){out.where=STORES[i][1];break;}
  if(!out.where)for(i=0;i<Math.min(3,lines.length);i++){
    if(/start|item|scan|receipt|copy|welcome|thank|checkout|member/i.test(lines[i]))continue;
    var letters=lines[i].replace(/[^A-Za-z ]/g,"").trim();
    if(letters.length>=4&&letters.length>=lines[i].length*0.7){out.where=letters.toLowerCase().replace(/\b[a-z]/g,function(c){return c.toUpperCase();}).slice(0,40);break;}
  }
  if((m=/(20\d{2})[\/\-.](\d{1,2})[\/\-.](\d{2})\s*([0-2]?\d):([0-5]\d)/.exec(text))){out.date=parseDate(m[1]+"-"+m[2]+"-"+m[3]);out.time=z(+m[4])+":"+m[5];}
  else{
    if((m=/(20\d{2})[\/\-.](\d{1,2})[\/\-.](\d{1,2})/.exec(text)))out.date=parseDate(m[1]+"-"+m[2]+"-"+m[3]);
    else if((m=/\b(\d{1,2})[\/\-](\d{1,2})[\/\-](20\d{2})\b/.exec(text)))out.date=parseDate(m[0]);
    if((m=/\b([01]?\d|2[0-3]):([0-5]\d)(?::[0-5]\d)?\b/.exec(text)))out.time=z(+m[1])+":"+m[2];
  }
  /* items: names and prices are collected as two ordered columns, then paired by position.
     On a creased or tilted receipt a price often lands on the neighbouring line, but its order in the column holds. */
  var names=[],prices=[],end=lines.length;
  for(i=0;i<lines.length;i++)if(/sub ?total/i.test(lines[i])||(/\btotal\b|^tax\b/i.test(lines[i])&&!/items|number/i.test(lines[i]))){end=i;break;}
  for(i=0;i<end;i++){
    var l=lines[i],pm=PRICE_END.exec(l),price=pm?Math.abs(parseAmount(pm[1]))*(pm[2]?-1:1):null,body=pm?l.slice(0,pm.index).trim():l;
    if(pm&&!body){prices.push(price);continue;}
    if(NOT_ITEM.test(l))continue;
    var a=/^(\d{2,})\s*(\/?\s*.*)$/.exec(body),id="",name="";
    if(a){
      id=a[1];name=a[2].trim();
      if(id.length>12){name="/"+id.slice(11)+(name?" "+name:"");id=id.slice(0,10);}
      if(!/[A-Za-z]/.test(name)&&name.charAt(0)!=="/")continue;
    }else if(pm&&/^[A-Za-z]/.test(body)&&body.length>=3)name=body;
    else continue;
    names.push({id:id.slice(0,24),name:fixName(name),own:price});
    if(pm)prices.push(price);
  }
  var zip=prices.length>=names.length;
  names.forEach(function(n,k){var c=zip?prices[k]:n.own;out.items.push({id:n.id,name:n.name,cost:c==null||isNaN(c)?0:Math.round(c*100)/100});});
  var sum=Math.round(out.items.reduce(function(t,it){return t+it.cost;},0)*100)/100,sub=null,tax=null,amts=[],tot=null;
  for(i=0;i<lines.length;i++){
    var q=PRICE_END.exec(lines[i]),v=q?Math.abs(parseAmount(q[1])):null;
    if(/sub ?total/i.test(lines[i])&&v){sub=v;for(var k2=i+1;k2<Math.min(i+4,lines.length);k2++){var q2=PRICE_END.exec(lines[k2]),v2=q2?Math.abs(parseAmount(q2[1])):null;if(v2&&v2<sub*0.2){tax=v2;break;}}}
    if(/amount\s*:?\s*\$?\d/i.test(lines[i])&&v)amts.push(v);
    if(/\btotal\b/i.test(lines[i])&&!/items|number|sub/i.test(lines[i])&&v&&tot==null)tot=v;
  }
  var one=amts.filter(function(x,k){return amts.indexOf(x)===k;});
  if(sub!=null)out.amount=Math.round((sub+(tax||0))*100)/100;
  else if(one.length===1)out.amount=one[0];
  else if(tot!=null)out.amount=tot;
  else if(sum>0)out.amount=sum;
  out.verified=out.items.length>0&&((sub!=null&&Math.abs(sum-sub)<0.011)||(sub==null&&out.amount!=null&&sum>0&&sum<=out.amount+0.001&&sum>=out.amount*0.85));
  if((m=/inv\w{3,5}\s*(?:number|no\.?|#)?\s*[:#]?\s*([A-Z0-9]{4,})/i.exec(text))||(m=/(?:receipt|trans(?:action)?)\s*(?:number|no\.?|#)\s*[:#]?\s*([A-Z0-9]{4,})/i.exec(text)))out.receipt_no=m[1];
  out.pay=/master ?card|visa|amex|american express/i.test(text)?"Credit card":/debit|interac/i.test(text)?"Debit":/\bcash\b/i.test(text)?"Cash":null;
  var real=out.items.filter(function(it){return it.cost>=0&&it.name.charAt(0)!=="/";}).map(function(it){return it.name.toLowerCase();});
  out.category=guessCat(out.where+" "+real.join(" "))||"";
  if(real.length)out.what=(real.slice(0,2).join(", ")+(real.length>2?" +"+(real.length-2)+" more":"")).replace(/^./,function(c){return c.toUpperCase();}).slice(0,120);
  return out;
}

/* Items are edited as plain lines: item ID | name | price | category */
function itemsToText(items){
  return fillItemCats((items||[]).map(function(it){return Object.assign({},it);})).map(function(it){return (it.id||"-")+" | "+(it.name||"")+" | "+(+it.cost||0).toFixed(2)+(it.cat?" | "+CATNAME[it.cat]:"");}).join("\n");
}
function textToItems(text){
  var out=[];
  (text||"").split(/\n/).forEach(function(line){
    var p=line.split("|").map(function(s){return s.trim();});
    if(!line.trim())return;
    var it={id:"",name:"",cost:0};
    if(p.length>=3){it.id=p[0]==="-"?"":p[0];it.name=p[1];it.cost=parseAmount(p[2]);if(p[3])it.cat=catFromLabel(p[3]);}
    else if(p.length===2){if(isNaN(parseAmount(p[1]))){it.id=p[0];it.name=p[1];}else{it.name=p[0];it.cost=parseAmount(p[1]);}}
    else it.name=p[0];
    if(isNaN(it.cost))it.cost=0;
    it.id=it.id.slice(0,24);it.name=it.name.slice(0,60);it.cost=Math.round(it.cost*100)/100;
    if(it.name||it.id)out.push(it);
  });
  return fillItemCats(out.slice(0,120));
}

/* ---------- render ---------- */
function render(){
  $("todayLabel").textContent=new Date().toLocaleDateString("en-CA",{weekday:"long",month:"long",day:"numeric"});
  var st=$("saveStatus");
  paintCloud();
  renderCheckin();renderTape();renderTabs();renderView();
}

function renderCheckin(){
  var box=$("checkin");box.textContent="";
  var pxc=pxCard();if(pxc){box.append(pxc);}
  var t=today(),mine=S.entries.filter(function(e){return e.date===t;}),ns=!!(S.days[t]&&S.days[t].noSpend);
  var head=mine.length?mine.length+(mine.length===1?" purchase":" purchases")+" logged today":ns?"Today is marked as a no-spend day":"What did you spend today?";
  var sub=mine.length?money(sum(mine))+" so far. Anything else?":ns?"Bought something after all? Log it and this clears.":"List every purchase: what, how much, where, why, and the receipt.";
  box.append(h("div",null,h("h2",{text:head}),h("p",{class:"muted",text:sub,style:"margin-top:4px"})));

  var week=h("div",{class:"week"}),missed=[];
  for(var i=6;i>=0;i--){
    (function(i){
      var d=new Date();d.setDate(d.getDate()-i);var ds=iso(d);
      var has=S.entries.some(function(e){return e.date===ds;}),nsd=!!(S.days[ds]&&S.days[ds].noSpend);
      var state=has?"logged":nsd?"nospend":(i===0?"":"missed");
      if(state==="missed")missed.push(d.toLocaleDateString("en-CA",{weekday:"short"}));
      var lab=d.toLocaleDateString("en-CA",{weekday:"short"}).slice(0,3);
      week.append(h("button",{type:"button",class:"day "+state+(i===0?" today":""),
        "aria-label":dayLabel(ds)+": "+(has?"logged":nsd?"no spending":"nothing logged")+". Log a purchase for this day.",
        onclick:function(){openChooser(ds);}},h("span",{text:lab}),h("span",{class:"dot"})));
    })(i);
  }
  box.append(week);
  if(S.ready&&missed.length)box.append(h("p",{class:"small",style:"color:var(--impulse);font-weight:600",text:"Nothing logged for "+missed.join(", ")+". Tap a day to fill it in."}));

  var streak=0,c=new Date();if(!covered(iso(c)))c.setDate(c.getDate()-1);
  while(streak<400&&covered(iso(c))){streak++;c.setDate(c.getDate()-1);}
  var row=h("div",{class:"btnrow"});
  row.append(h("button",{type:"button",class:"btn primary",disabled:!S.ready,text:"Log a purchase",onclick:function(){openChooser(today());}}));
  if(!mine.length&&!ns)row.append(h("button",{type:"button",class:"btn quiet",disabled:!S.ready,text:"Nothing spent today",onclick:function(){guard(store.setNoSpend(t,true));}}));
  if(ns&&!mine.length)row.append(h("button",{type:"button",class:"btn quiet",text:"Undo no-spend",onclick:function(){guard(store.setNoSpend(t,false));}}));
  box.append(row);
  var soon=S.entries.filter(function(e){return e.returnBy&&daysLeft(e.returnBy)>=0&&daysLeft(e.returnBy)<=7&&!fullyReturned(e);});
  if(soon.length)box.append(h("button",{type:"button",class:"chip impulse",style:"align-self:flex-start",text:soon.length+(soon.length===1?" return deadline":" return deadlines")+" within 7 days",onclick:function(){S.tab="returns";render();}}));
  if(streak>1)box.append(h("p",{class:"small muted mono",text:streak+" days in a row accounted for"}));
}
function guard(p){p.catch(function(e){toast(saveErr(e));});}

function renderTape(){
  var box=$("tape");box.textContent="";
  var m=S.month,list=S.entries.filter(function(e){return ym(e.date||"")===m;});
  var total=sum(list),isNow=m===ym(today());
  box.append(h("div",{class:"tapehead"},
    h("button",{type:"button","aria-label":"Previous month",text:"◀",onclick:function(){S.month=shiftMonth(m,-1);render();}}),
    h("span",{text:monthLabel(m)}),
    h("button",{type:"button","aria-label":"Next month",text:"▶",disabled:isNow,onclick:function(){S.month=shiftMonth(m,1);render();}})));
  box.append(h("div",null,h("div",{class:"sub",text:"Total spent"}),h("div",{class:"total",text:money(total)})));
  if(!list.length){
    box.append(h("hr",{class:"rule"}),h("p",{style:"font-family:var(--body)",class:"muted",text:"Nothing logged for this month. Once you log purchases, this receipt shows where the money went."}));
    return;
  }
  var p=m.split("-"),dim=new Date(+p[0],+p[1],0).getDate(),daysSoFar=isNow?new Date().getDate():dim;
  var prev=sum(S.entries.filter(function(e){return ym(e.date||"")===shiftMonth(m,-1);}));
  box.append(ln("Purchases",String(list.length)),ln("Average per day",money(total/daysSoFar)));
  if(prev>0){var diff=total-prev;box.append(ln("Against "+monthLabel(shiftMonth(m,-1)).split(" ")[0],(diff>=0?"+":"−")+money(Math.abs(diff))));}

  var by=spendByCat(list);
  var cats=Object.keys(by).map(function(k){return [k,by[k]];}).filter(function(c){return Math.abs(c[1])>=0.005;}).sort(function(a,b){return b[1]-a[1];});
  if(!cats.length)cats=[["unsorted",0]];
  var topName=CATNAME[cats[0][0]]||"Unsorted",topPct=total?Math.round(cats[0][1]/total*100):0;
  box.append(h("hr",{class:"rule"}),h("p",{class:"callout",text:"Most of your money went to "+topName+": "+money(cats[0][1])+", "+topPct+"% of the month."}));
  cats.forEach(function(c){
    var pct=total?c[1]/total*100:0;
    box.append(h("div",{class:"catrow"},ln(CATNAME[c[0]]||"Unsorted",money(c[1])+"  "+Math.round(pct)+"%"),h("div",{class:"bar"},h("i",{style:"width:"+pct.toFixed(1)+"%"}))));
  });

  var why={need:0,want:0,impulse:0,none:0};list.forEach(function(e){why[WHYNAME[e.why]?e.why:"none"]+=net(e);});
  var split=h("div",{class:"split",role:"img","aria-label":"Need "+money(why.need)+", want "+money(why.want)+", impulse "+money(why.impulse)});
  [["need","--need"],["want","--want"],["impulse","--impulse"]].forEach(function(w){if(why[w[0]]>0)split.append(h("i",{style:"width:"+(why[w[0]]/total*100).toFixed(1)+"%;background:var("+w[1]+")"}));});
  var legend=h("div",{class:"legend"});
  [["need","--need","Need"],["want","--want","Want"],["impulse","--impulse","Impulse"]].forEach(function(w){legend.append(h("span",null,h("b",{style:"background:var("+w[1]+")"}),w[2]+" "+money(why[w[0]])));});
  if(why.none>0)legend.append(h("span",{class:"muted",text:"No reason given "+money(why.none)}));
  box.append(h("hr",{class:"rule"}),h("div",{class:"sub",text:"Need, want or impulse"}),split,legend);

  var places={};list.forEach(function(e){var k=(e.where||"").trim();if(k)places[k]=(places[k]||0)+net(e);});
  var tops=Object.keys(places).map(function(k){return [k,places[k]];}).sort(function(a,b){return b[1]-a[1];}).slice(0,3);
  if(tops.length){box.append(h("hr",{class:"rule"}),h("div",{class:"sub",text:"Where it went"}));tops.forEach(function(t){box.append(ln(t[0],money(t[1])));});}
  var miss=list.filter(receiptMissing).length;
  box.append(h("hr",{class:"rule"}));
  var backSum=list.reduce(function(t,e){return t+refunded(e);},0);
  if(backSum>0)box.append(ln("Returned and refunded","−"+money(backSum)));
  box.append(ln("Receipts missing",String(miss)));
}
function ln(k,v){return h("div",{class:"ln"},h("span",{class:"k",text:k}),h("span",{class:"lead"}),h("span",{text:v}));}

function renderTabs(){
  var nav=$("tabs");nav.textContent="";
  var need=S.entries.filter(function(e){return e.needsDetails;}).length;
  var ret=S.entries.filter(function(e){return e.returnBy&&daysLeft(e.returnBy)>=0&&!fullyReturned(e);}).length;
  [["log","Purchases",0],["inbox","Needs details",need],["returns","Returns",ret],["bills","Bills",0],["import","Bank import",0],["settings","Account & backup",0]].forEach(function(t){
    nav.append(h("button",{type:"button",class:"tab",role:"tab","aria-selected":S.tab===t[0]?"true":"false",onclick:function(){S.tab=t[0];render();}},t[1],t[2]?h("span",{class:"count",text:"("+t[2]+")"}):null));
  });
}

function entryRow(e){
  var metaBits=[];
  if(e.what&&e.where)metaBits.push(e.where);
  if(e.category)metaBits.push(CATNAME[e.category]||e.category);
  if(e.pay)metaBits.push(e.pay);
  if(e.time)metaBits.push(e.time);
  if(e.note)metaBits.push("“"+e.note+"”");
  var chips=h("div",{class:"chips"});
  if(WHYNAME[e.why])chips.append(h("span",{class:"chip "+e.why,text:WHYNAME[e.why]}));
  var back=refunded(e),gone=fullyReturned(e),canReturn=!gone&&(e.returnAny||(e.returnBy&&daysLeft(e.returnBy)>=0));
  if(back>0)chips.append(h("span",{class:"chip need",text:(gone?"Returned":"Part returned")+" · "+money(back)+" back"}));
  if(e.ret)chips.append(h("button",{type:"button",class:"chip",text:"Change return",onclick:function(){openReturn(e,-1);}}));
  if(canReturn)chips.append(h("button",{type:"button",class:"chip has",text:(e.items&&e.items.length)?"Return everything":"Mark as returned",onclick:function(){openReturn(e,-1);}}));
  if(!gone&&e.returnAny)chips.append(h("span",{class:"chip need",text:"Returnable any time"}));
  if(!gone&&e.returnBy){var dl=daysLeft(e.returnBy);chips.append(h("span",{class:"chip "+(dl<0?"":dl<=7?"impulse":"need"),text:dl<0?"Return window closed":"Return by "+dayLabel(e.returnBy)+" · "+dl+(dl===1?" day left":" days left")}));}
  if(e.scanned)chips.append(h("button",{type:"button",class:"chip want",text:"Scanned: check it",onclick:function(){openEntry(e);}}));
  if(e.needsDetails)chips.append(h("button",{type:"button",class:"chip miss",text:"Add details",onclick:function(){openEntry(e);}}));
  if(e.receiptId){
    chips.append(h("button",{type:"button",class:"chip has",text:e.receiptId2?"View receipt (2 photos)":"View receipt",onclick:function(){showReceipt(e.receiptId,e.receiptId2);}}));
  }else if(e.noReceipt)chips.append(h("span",{class:"chip",text:"No receipt"}));
  else chips.append(h("button",{type:"button",class:"chip miss",text:"Receipt missing",onclick:function(){openEntry(e);}}));
  return h("div",{class:"row"},
    h("button",{type:"button",class:"rowmain","aria-label":"Edit "+title(e),onclick:function(){openEntry(e);}},
      h("span",{class:"what",text:title(e)}),h("span",{class:"amt",text:money(net(e))}),
      metaBits.length?h("span",{class:"meta",text:metaBits.join(" · ")}):null),
    chips,itemsBlock(e));
}
function itemsBlock(e){
  if(!Array.isArray(e.items)||!e.items.length)return null;
  var d=h("details",{class:"items",open:!!(S.q&&S.q.trim())},h("summary",{text:e.items.length+(e.items.length===1?" line":" lines")+" from the receipt"}));
  e.items.forEach(function(it,k){var c=+it.cost||0;
    d.append(h("div",{class:"ln mono small"},h("span",{class:"k",text:(it.id?it.id+"  ":"")+(it.name||"Item")+(it.cat?"  ·  "+CATNAME[it.cat]:"")}),h("span",{class:"lead"}),h("span",{text:(c<0?"−":"")+money(Math.abs(c))}),retBtn(e,it,k)));});
  return d;
}

/* A receipt is a duplicate only when receipt number, date, time, total and every item line all match. */
function itemKey(items){
  return (items||[]).filter(function(i){return i&&i.id;}).map(function(i){return i.id+"|"+(+i.cost||0).toFixed(2);}).sort().join(",");
}
function receiptKey(r,date){return [r.no||"",date||"",r.time||"",(+r.total||0).toFixed(2)].join("|");}
function findDuplicate(meta,items,date,skipId){
  var want=receiptKey(meta,date),group=S.entries.filter(function(e){return e.receipt&&e.id!==skipId&&receiptKey(e.receipt,e.date)===want;});
  if(!group.length)return null;
  var have=[];group.forEach(function(e){have=have.concat(e.items||[]);});
  return itemKey(have)===itemKey(items)?group[0]:null;
}
function dupMsg(d){return "You already logged this receipt: "+title(d)+" on "+dayLabel(d.date)+", receipt total "+money(d.receipt.total)+". Same receipt number, time, total and items. Tap Save anyway only if it really is a separate purchase.";}
function renderView(){
  var v=$("view");v.textContent="";
  if(S.tab!==lastTab){lastTab=S.tab;T("tab_"+S.tab);}
  if(S.tab==="log")viewLog(v);else if(S.tab==="inbox")viewInbox(v);else if(S.tab==="bills")viewBills(v);else if(S.tab==="returns")viewReturns(v);else if(S.tab==="import")viewImport(v);else viewSettings(v);
}

function viewLog(v){
  var sb=h("input",{type:"search",id:"q",placeholder:"Search item, item ID, store, receipt number","aria-label":"Search all purchases",autocomplete:"off"});
  sb.value=S.q||"";
  var box=h("div",{id:"logList"});
  sb.addEventListener("input",function(){S.q=sb.value;box.textContent="";fillLog(box);});
  v.append(sb,box);fillLog(box);
}
function fillLog(v){
  var q=(S.q||"").trim().toLowerCase();
  var list=q?S.entries.filter(function(e){return matches(e,q);}):S.entries.filter(function(e){return ym(e.date||"")===S.month;});
  v.append(h("h2",{text:q?list.length+(list.length===1?" match":" matches")+" across all months":"Purchases in "+monthLabel(S.month)}));
  if(!list.length){v.append(h("p",{class:"empty",text:q?"Nothing matches that search.":S.ready?"No purchases logged for this month yet. Use “Log a purchase” above, or bring in a bank export under Bank import.":"Loading your purchases…"}));return;}
  var cur=null;
  list.forEach(function(e){
    if(e.date!==cur){cur=e.date;var dayTotal=sum(list.filter(function(x){return x.date===cur;}));
      v.append(h("div",{class:"dayhead"},h("span",{text:dayLabel(cur)}),h("span",{text:money(dayTotal)})));}
    v.append(entryRow(e));
  });
  var btn=h("button",{type:"button",class:"btn quiet",text:q?"Copy these matches as CSV":"Copy this month as CSV",onclick:function(){
    var rows=[["date","time","what","where","entry_total","category","paid_with","why","reason","receipt","return_by","item_id","item_name","item_cost","item_category","returned_on","refund"]];
    list.forEach(function(e){
      var base=[e.date,e.time||"",e.what||"",e.where||"",(+e.amount||0).toFixed(2),CATNAME[e.category]||"",e.pay||"",WHYNAME[e.why]||"",e.note||"",e.receiptId?"attached":e.noReceipt?"none":"missing",e.returnAny?"any time":(e.returnBy||"")];
      if(Array.isArray(e.items)&&e.items.length)e.items.forEach(function(it){rows.push(base.concat([it.id||"",it.name||"",(+it.cost||0).toFixed(2),CATNAME[it.cat]||"",it.ret?it.ret.d:"",it.ret?(+it.ret.amt).toFixed(2):""]));});
      else rows.push(base.concat(["","","","",e.ret?e.ret.d:"",e.ret?(+e.ret.amt).toFixed(2):""]));
    });
    var csv=rows.map(function(r){return r.map(function(c){c=String(c);return /[",\n]/.test(c)?'"'+c.replace(/"/g,'""')+'"':c;}).join(",");}).join("\n");
    try{navigator.clipboard.writeText(csv).then(function(){btn.textContent="Copied";},function(){toast("Copying was blocked in this view.");});}catch(e){toast("Copying was blocked in this view.");}
  }});
  v.append(h("div",{class:"btnrow",style:"margin-top:8px"},btn));
}

function viewInbox(v){
  var list=S.entries.filter(function(e){return e.needsDetails;});
  v.append(h("h2",{text:"Needs details"}));
  if(!list.length){v.append(h("p",{class:"empty",text:"Nothing waiting. Rows you bring in from a bank export land here until you say what each one was, why you bought it, and attach the receipt."}));return;}
  v.append(h("p",{class:"muted",text:"Your bank knows the amount. Say what each one was and why."}));
  list.forEach(function(e){
    v.append(h("div",{class:"dayhead"},h("span",{text:dayLabel(e.date)}),h("span",{text:money(e.amount)})));
    v.append(entryRow(e));
  });
}

function viewBills(v){
  var m=ym(today()),day=new Date().getDate();
  v.append(h("h2",{text:"Recurring bills"}));
  var paidOf=function(b){return S.entries.find(function(e){return e.billId===b.id&&ym(e.date||"")===m;});};
  if(S.bills.length){
    var all=S.bills.reduce(function(t,b){return t+(+b.amount||0);},0);
    var left=S.bills.reduce(function(t,b){return t+(paidOf(b)?0:(+b.amount||0));},0);
    v.append(h("p",{class:"mono small",text:money(all)+" a month in fixed bills · "+money(left)+" still to pay in "+monthLabel(m).split(" ")[0]}));
  }else v.append(h("p",{class:"empty",text:"Add the bills that repeat every month: rent, phone, insurance, subscriptions. Each month this list shows which are paid and which are coming up."}));
  S.bills.slice().sort(function(a,b){return (a.dueDay||0)-(b.dueDay||0);}).forEach(function(b){
    var paid=paidOf(b),chips=h("div",{class:"chips"});
    if(paid)chips.append(h("span",{class:"chip need",text:"Paid "+dayLabel(paid.date)}));
    else{
      var d=(b.dueDay||1)-day;
      chips.append(h("span",{class:"chip "+(d<0?"impulse":d<=3?"want":""),text:d<0?"Overdue by "+(-d)+(d===-1?" day":" days"):d===0?"Due today":"Due in "+d+(d===1?" day":" days")}));
      chips.append(h("button",{type:"button",class:"chip has",text:"Mark paid",onclick:function(){openEntry({what:b.name,where:b.name,amount:b.amount,category:b.category,why:"need",billId:b.id});}}));
    }
    v.append(h("div",{class:"row"},
      h("button",{type:"button",class:"rowmain","aria-label":"Edit bill "+b.name,onclick:function(){openBill(b);}},
        h("span",{class:"what",text:b.name}),h("span",{class:"amt",text:money(b.amount)}),
        h("span",{class:"meta",text:"Due on day "+(b.dueDay||1)+" · "+(CATNAME[b.category]||"Other")})),chips));
  });
  v.append(h("div",{class:"btnrow"},h("button",{type:"button",class:"btn",disabled:!S.ready,text:"Add a bill",onclick:function(){openBill(null);}})));
  if(S.bills.length)v.append(calBtn("Add bill due dates to my calendar",billEvents()));
}

/* ---------- bank import ---------- */
function parseCSV(text){
  var first=text.split(/\r?\n/)[0]||"",delim=",";
  [";","\t"].forEach(function(d){if(first.split(d).length>first.split(delim).length)delim=d;});
  var rows=[],row=[],cell="",q=false;
  for(var i=0;i<text.length;i++){var ch=text[i];
    if(q){if(ch==='"'){if(text[i+1]==='"'){cell+='"';i++;}else q=false;}else cell+=ch;}
    else if(ch==='"')q=true;
    else if(ch===delim){row.push(cell);cell="";}
    else if(ch==="\n"||ch==="\r"){if(ch==="\r"&&text[i+1]==="\n")i++;row.push(cell);cell="";if(row.some(function(c){return c.trim();}))rows.push(row);row=[];}
    else cell+=ch;}
  row.push(cell);if(row.some(function(c){return c.trim();}))rows.push(row);
  return rows.map(function(r){return r.map(function(c){return c.trim();});});
}
function parseAmount(s){
  if(s==null)return NaN;s=String(s).trim();if(!s)return NaN;
  var neg=/^\(.*\)$/.test(s)||/^-/.test(s)||/-$/.test(s)||/\bDR\b/i.test(s);
  var n=s.replace(/[^0-9.,]/g,"");if(!n||!/\d/.test(n))return NaN;
  if(/[a-z]{2,}/i.test(s.replace(/\b(CR|DR|CAD|USD)\b/gi,"")))return NaN;
  if(/,\d{2}$/.test(n)&&n.indexOf(".")<0)n=n.replace(/\./g,"").replace(",",".");else n=n.replace(/,/g,"");
  var v=parseFloat(n);return isNaN(v)?NaN:(neg?-v:v);
}
function parseDate(s){
  if(!s)return null;s=String(s).trim();var m,y,mo,d;
  if((m=/^(\d{4})[-\/.](\d{1,2})[-\/.](\d{1,2})/.exec(s))){y=+m[1];mo=+m[2];d=+m[3];}
  else if((m=/^(\d{1,2})[-\/.](\d{1,2})[-\/.](\d{2,4})$/.exec(s))){var a=+m[1],b=+m[2];y=+m[3];if(y<100)y+=2000;if(a>12){d=a;mo=b;}else{mo=a;d=b;}}
  else if((m=/^(\d{4})(\d{2})(\d{2})$/.exec(s))){y=+m[1];mo=+m[2];d=+m[3];}
  else if(/^(?:\d{1,2}[\s-])?(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*[\s.,-]+\d{1,4}(?:[\s,.-]+\d{2,4})?$/i.test(s)){var t=Date.parse(s.replace(/-/g," "));if(isNaN(t))return null;return iso(new Date(t));}
  else return null;
  if(y<2000||y>2100||mo<1||mo>12||d<1||d>31)return null;
  return y+"-"+z(mo)+"-"+z(d);
}
function extractRows(text,flip){
  var rows=parseCSV(text),out=[],skipped=0,single=[],usedSingle=false;
  if(!rows.length)return {rows:[],skipped:0,single:false};
  var col={};
  if(!rows[0].some(function(c){return parseDate(c);})){
    rows[0].forEach(function(name,i){
      if(col.date==null&&/date/i.test(name))col.date=i;
      else if(col.debit==null&&/debit|withdraw|money out|paid out|spent/i.test(name))col.debit=i;
      else if(col.credit==null&&/credit|deposit|money in|paid in/i.test(name))col.credit=i;
      else if(col.amount==null&&/amount|^amt|cad\$?/i.test(name))col.amount=i;
      else if(col.desc==null&&/desc|payee|merchant|name|memo|detail|transaction/i.test(name))col.desc=i;
    });
    rows=rows.slice(1);
  }
  rows.forEach(function(r){
    var di=col.date!=null?col.date:r.findIndex(function(c){return parseDate(c);});
    var date=di>=0?parseDate(r[di]):null;
    if(!date){skipped++;return;}
    var si=col.desc;
    if(si==null){var best=-1,len=0;r.forEach(function(c,i){if(i!==di&&c&&isNaN(parseAmount(c))&&!parseDate(c)&&c.length>len){len=c.length;best=i;}});si=best;}
    var desc=si>=0?(r[si]||""):"";
    if(col.debit!=null){var v=Math.abs(parseAmount(r[col.debit]));if(v>0)out.push({date:date,desc:desc,amount:v});else skipped++;return;}
    if(col.amount!=null){usedSingle=true;single.push({date:date,desc:desc,v:parseAmount(r[col.amount])});return;}
    var after=r.slice(si+1).filter(function(c,i){return (si+1+i)!==di;});
    if(after.length>=2){var deb=Math.abs(parseAmount(after[0]));if(deb>0)out.push({date:date,desc:desc,amount:deb});else skipped++;return;}
    usedSingle=true;single.push({date:date,desc:desc,v:parseAmount(after[0])});
  });
  if(single.length){
    var sign=single.some(function(x){return x.v<0;})?-1:1;if(flip)sign=-sign;
    single.forEach(function(x){if(!isNaN(x.v)&&x.v*sign>0)out.push({date:x.date,desc:x.desc,amount:Math.abs(x.v)});else skipped++;});
  }
  return {rows:out,skipped:skipped,single:usedSingle};
}
function guessCat(d){
  if(/tim hortons|mcdonald|starbucks|uber ?eats|doordash|skip ?the|restaurant|pizza|subway|a&w|wendy|popeyes|cafe|coffee|sushi|shawarma/i.test(d))return "eating";
  if(/loblaw|no ?frills|metro|sobeys|freshco|walmart|costco|food basics|farm boy|t&t|grocery/i.test(d))return "groceries";
  if(/netflix|spotify|disney|apple\.com|prime video|youtube|crave|subscription/i.test(d))return "subs";
  if(/uber|lyft|presto|ttc|go transit|petro|esso|shell|parking|407 ?etr|gas/i.test(d))return "transport";
  if(/hydro|enbridge|rogers|bell |telus|fido|freedom|rent|insurance/i.test(d))return "housing";
  if(/amazon|amzn|best buy|canadian tire|ikea|winners|dollarama/i.test(d))return "shopping";
  if(/shoppers|pharma|rexall|dental|clinic/i.test(d))return "health";
  return "";
}
function tidy(d){return d.replace(/\s+/g," ").trim().slice(0,70);}
function importKey(r){return r.date+"|"+r.amount.toFixed(2)+"|"+tidy(r.desc).toLowerCase();}

function checkImport(){
  var res=extractRows(S.importText,S.importFlip);
  var have={};S.entries.forEach(function(e){if(e.importKey)have[e.importKey]=1;});
  var fresh=[],dupes=0;
  res.rows.forEach(function(r){var k=importKey(r);if(have[k]){dupes++;}else{have[k]=1;fresh.push(r);}});
  T("bank_import_preview");
  S.importPreview={fresh:fresh.slice(0,300),over:Math.max(0,fresh.length-300),dupes:dupes,skipped:res.skipped,single:res.single};
  render();
}
async function runImport(){
  var p=S.importPreview;if(!p||!p.fresh.length||S.importing)return;
  S.importing=true;render();
  var done=0;
  try{
    for(var i=0;i<p.fresh.length;i++){var r=p.fresh[i];
      await store.saveEntry({what:"",where:"",bankDesc:tidy(r.desc),amount:r.amount,date:r.date,time:"",category:guessCat(r.desc),pay:"",why:"",note:"",needsDetails:true,source:"import",importKey:importKey(r),createdAt:Date.now()+i});
      done++;}
    toast(done+" rows brought in. They're waiting under Needs details.");
    S.importText="";S.importPreview=null;S.tab="inbox";T("bank_import_done");
  }catch(e){toast(saveErr(e)+" "+done+" rows were saved before it stopped.");S.importPreview=null;}
  S.importing=false;render();
}
function viewImport(v){
  v.append(h("h2",{text:"Bring in a bank export"}));
  v.append(h("p",{class:"muted",text:"This app can't connect to your bank. Download your transactions as a CSV from online banking, then choose the file or paste it here. Every money-out row is added, and the app asks you what each one was."}));
  var ta=h("textarea",{id:"imp-text","aria-label":"Pasted bank CSV",placeholder:"11/14/2026,TIM HORTONS #1234,4.85,,1520.11",spellcheck:"false"});
  ta.value=S.importText;
  ta.addEventListener("input",function(){S.importText=ta.value;S.importPreview=null;});
  var file=h("input",{type:"file",id:"imp-file",accept:".csv,.txt,text/csv,text/plain","aria-label":"Bank CSV file"});
  file.addEventListener("change",function(){var f=file.files&&file.files[0];if(!f)return;f.text().then(function(t){S.importText=t;checkImport();},function(){toast("That file couldn't be read. Try pasting the rows instead.");});});
  var panel=h("div",{class:"panel"},h("div",{class:"field"},h("label",{for:"imp-file",text:"CSV file from your bank"}),file),h("div",{class:"field"},h("label",{for:"imp-text",text:"Or paste the rows"}),ta),
    h("div",{class:"btnrow"},h("button",{type:"button",class:"btn",text:"Check rows",disabled:!S.ready||S.importing,onclick:function(){if(!S.importText.trim()){toast("Choose a file or paste some rows first.");return;}checkImport();}})));
  v.append(panel);
  var p=S.importPreview;
  if(p){
    var box=h("div",{class:"panel"});
    box.append(h("h3",{text:p.fresh.length?p.fresh.length+" new money-out rows found":"No new money-out rows found"}));
    var bits=[];if(p.dupes)bits.push(p.dupes+" already imported");if(p.skipped)bits.push(p.skipped+" skipped (deposits, headers or unreadable rows)");if(p.over)bits.push(p.over+" more than 300, import those next");
    if(bits.length)box.append(h("p",{class:"small muted",text:bits.join(" · ")}));
    if(p.single){
      var cb=h("input",{type:"checkbox",id:"imp-flip"});cb.checked=S.importFlip;
      cb.addEventListener("change",function(){S.importFlip=cb.checked;checkImport();});
      box.append(h("label",{class:"check",for:"imp-flip"},cb,"These look like deposits, not purchases. Flip the sign."));
    }
    p.fresh.slice(0,5).forEach(function(r){box.append(h("div",{class:"ln mono small"},h("span",{class:"k",text:r.date+"  "+tidy(r.desc).slice(0,28)}),h("span",{class:"lead"}),h("span",{text:money(r.amount)})));});
    if(p.fresh.length>5)box.append(h("p",{class:"small muted",text:"and "+(p.fresh.length-5)+" more"}));
    if(p.fresh.length)box.append(h("div",{class:"btnrow"},h("button",{type:"button",class:"btn primary",disabled:S.importing,text:S.importing?"Bringing rows in…":"Import "+p.fresh.length+" rows",onclick:runImport})));
    v.append(box);
  }
}

/* ---------- entry form ---------- */
function fillSelect(sel,opts,blank){sel.textContent="";sel.append(h("option",{value:"",text:blank}));opts.forEach(function(o){sel.append(h("option",{value:o[0],text:o[1]}));});}
function receiptCaps(){
  var f=$("f-receipt"),note=$("f-receiptNote");
  f.hidden=!(assets||canReadImages);
  note.textContent=assets?"":(canReadImages?"This view can read a receipt photo but can't keep it.":"Receipt photos can't be stored in this view. Tick the box if there isn't one.");
  if(editing&&editing.receiptId&&!pendingBlob)note.textContent="A receipt is attached. Choose a file to replace it.";
  $("f-read").hidden=!(pendingBlob&&pendingType==="image"&&canReadImages);
}
function clearPending(){pendingBlob2=null;$("f-receipt2").value="";$("f-receipt2Note").textContent="";pendingBlob=null;pendingType=null;pendingItems=null;pendingReceipt=null;dupOk=false;if(previewUrl){URL.revokeObjectURL(previewUrl);previewUrl=null;}var p=$("f-preview");p.hidden=true;p.removeAttribute("src");$("f-receipt").value="";}
function openEntry(e){
  if(!S.ready){toast("Still connecting. Try again in a moment.");return;}
  editing=e&&e.id?e:null;deleteArmed=false;clearPending();
  var now=new Date();
  $("entryTitle").textContent=editing?(editing.needsDetails?"What was this?":"Edit purchase"):(e&&e.billId?"Mark bill as paid":"Log a purchase");
  var bank=$("f-bank");bank.hidden=!(e&&e.bankDesc);bank.textContent=e&&e.bankDesc?"Your bank calls it: "+e.bankDesc:"";
  $("f-what").value=(e&&e.what)||"";$("f-where").value=(e&&e.where)||"";
  $("f-amount").value=e&&e.amount!=null?(+e.amount).toFixed(2):"";
  $("f-date").value=(e&&e.date)||today();
  $("f-time").value=e&&e.id?(e.time||""):(e&&e.date&&e.date!==today()?"":z(now.getHours())+":"+z(now.getMinutes()));
  $("f-cat").value=(e&&e.category)||"";$("f-pay").value=(e&&e.pay)||"";
  ["need","want","impulse"].forEach(function(w){$("f-why-"+w).checked=!!(e&&e.why===w);});
  $("f-note").value=(e&&e.note)||"";$("f-return").value=(e&&e.returnBy)||"";$("f-items").value=itemsToText(e&&e.items);$("f-returnAny").checked=!!(e&&e.returnAny);returnTouched=!!(e&&e.returnSet==="manual");returnAuto=!!(e&&e.returnSet==="auto");$("f-returnNote").textContent=returnAuto?"Auto-filled from the store's usual policy. Edit it if your receipt says otherwise.":"";$("f-receipt2Note").textContent=(editing&&editing.receiptId2)?"A second photo is attached. Choose a file to replace it.":"";$("f-noreceipt").checked=!!(e&&e.noReceipt);
  $("f-err").hidden=true;$("f-save").disabled=false;$("f-save").textContent="Save purchase";
  var del=$("f-delete");del.hidden=!editing;del.textContent="Delete";
  $("entryDlg").dataset.bill=(e&&e.billId)||"";
  receiptCaps();
  $("entryDlg").showModal();
}
async function shrink(file){
  try{
    var bmp=await createImageBitmap(file),s=Math.min(1,2400/Math.max(bmp.width,bmp.height));
    var c=document.createElement("canvas");c.width=Math.round(bmp.width*s);c.height=Math.round(bmp.height*s);
    c.getContext("2d").drawImage(bmp,0,0,c.width,c.height);
    var blob=await new Promise(function(res){c.toBlob(res,"image/jpeg",0.9);});
    return blob||file;
  }catch(e){return file;}
}
$("f-receipt").addEventListener("change",async function(){
  var f=this.files&&this.files[0];if(!f)return;
  if(f.size>20*1024*1024){toast("That file is over 20 MB. Choose a smaller one.");this.value="";return;}
  if(f.type==="application/pdf"){pendingBlob=f;pendingType="pdf";$("f-preview").hidden=true;$("f-receiptNote").textContent="PDF ready: "+f.name;}
  else{
    pendingBlob=await shrink(f);pendingType="image";
    if(previewUrl)URL.revokeObjectURL(previewUrl);previewUrl=URL.createObjectURL(pendingBlob);
    var p=$("f-preview");p.src=previewUrl;p.hidden=false;$("f-receiptNote").textContent="";
  }
  $("f-noreceipt").checked=false;
  $("f-read").hidden=!(pendingType==="image"&&canReadImages);
});
$("f-read").addEventListener("click",async function(){
  if(!sample||!pendingBlob)return;
  var btn=this,note=$("f-receiptNote");btn.disabled=true;btn.textContent="Reading the receipt…";
  readCtl=new AbortController();
  try{
    var r=await sample.json('The image is a store receipt or a bill. Reply with only one JSON object with these keys: "where" (store or company name), "what" (what was bought, at most 6 words), "amount" (total paid, a number), "date" ("YYYY-MM-DD" or null), "category" (one of: '+CATS.map(function(c){return c[0];}).join(", ")+'), "pay" (one of: '+PAYS.join(", ")+', or null). Use null for anything you cannot read. Example: {"where":"Metro","what":"Weekly groceries","amount":84.12,"date":"2026-11-14","category":"groceries","pay":"Debit"}',{images:[pendingBlob],modelTier:"quick",signal:readCtl.signal});
    if(r&&typeof r==="object"){
      if(r.where)$("f-where").value=String(r.where).slice(0,80);
      if(r.what&&!$("f-what").value)$("f-what").value=String(r.what).slice(0,120);
      var a=parseFloat(r.amount);if(a>0)$("f-amount").value=a.toFixed(2);
      if(r.date&&parseDate(String(r.date)))$("f-date").value=parseDate(String(r.date));
      if(r.category&&CATNAME[r.category])$("f-cat").value=r.category;
      if(r.pay&&PAYS.indexOf(r.pay)>=0)$("f-pay").value=r.pay;
      if(Array.isArray(r.items)){pendingItems=r.items.length?r.items:null;$("f-items").value=itemsToText(r.items);}
      var tm=/^(\d{1,2}):(\d{2})/.exec(String(r.time||""));if(tm)$("f-time").value=z(+tm[1])+":"+tm[2];
      pendingReceipt={no:r.receipt_no==null?"":String(r.receipt_no).slice(0,40),time:tm?z(+tm[1])+":"+tm[2]:"",total:a>0?Math.round(a*100)/100:0};dupOk=false;
      suggestReturn();
      readOk=true;note.textContent=r.verified?"Read on this phone. The item prices add up to the receipt total. Check the names, then save.":"Read on this phone. The item prices do not add up to the total, so check each line before saving.";
    }
  }catch(e){
    var c=e&&e.code;
    if(c==="cancelled"){}
    else if(c==="not_granted"||c==="sampling_disabled"||c==="images_unavailable"||c==="not_declared"||c==="capability_disabled"||c==="capability_removed"){canReadImages=false;btn.hidden=true;note.textContent="Receipt reading isn't available here. Type the details in.";}
    else if(c==="rate_limited")note.textContent="Too many requests right now. Type the details in, or try again later.";
    else if(c==="image_rejected")note.textContent="That photo couldn't be read. Try a clearer one.";
    else note.textContent="Couldn't read that receipt. Type the details in, or try again.";
  }
  btn.disabled=false;btn.textContent="Read this receipt on the phone";
  if(autoScan){
    autoScan=false;
    if(readOk&&$("entryDlg").open&&$("f-err").hidden&&$("f-what").value.trim()&&parseFloat($("f-amount").value)>0){$("entryTitle").textContent="Check the details";}
    else if($("entryDlg").open)$("entryTitle").textContent=readOk?"Check the details":"Add the details";
  }
});
function closeEntry(){if(readCtl)readCtl.abort();clearPending();editing=null;$("entryDlg").close();}
$("f-cancel").addEventListener("click",closeEntry);
$("entryDlg").addEventListener("cancel",function(){if(readCtl)readCtl.abort();clearPending();editing=null;});
$("entryForm").addEventListener("submit",async function(ev){
  ev.preventDefault();
  var err=$("f-err"),save=$("f-save");
  var what=$("f-what").value.trim(),amount=parseFloat($("f-amount").value),date=$("f-date").value;
  var bad=!what?"Say what you bought.":!(amount>0)?"Enter how much it cost.":!parseDate(date)?"Pick the date.":date>today()?"That date is in the future. Pick today or earlier.":"";
  if(bad){err.textContent=bad;err.hidden=false;return;}
  err.hidden=true;save.disabled=true;save.textContent="Saving…";
  var why=["need","want","impulse"].filter(function(w){return $("f-why-"+w).checked;})[0]||"";
  var e=Object.assign({},editing||{},{what:what,where:$("f-where").value.trim(),amount:Math.round(amount*100)/100,date:date,time:$("f-time").value||"",category:$("f-cat").value,pay:$("f-pay").value,why:why,note:$("f-note").value.trim(),noReceipt:$("f-noreceipt").checked,needsDetails:false});
  if(!e.createdAt)e.createdAt=Date.now();
  if(!returnTouched)suggestReturn();
  e.returnAny=$("f-returnAny").checked;e.returnBy=e.returnAny?"":(parseDate($("f-return").value)||"");e.returnSet=returnTouched?"manual":(returnAuto?"auto":"");
  if(!e.source)e.source="manual";
  e.scanned=!!scanSaved;scanSaved=false;
  var bill=$("entryDlg").dataset.bill;if(bill)e.billId=bill;
  e.items=textToItems($("f-items").value);keepReturns(e.items,editing&&editing.items);
  if(pendingReceipt){
    pendingReceipt.total=e.amount;e.receipt=pendingReceipt;
    var dup=findDuplicate(pendingReceipt,e.items,date,editing&&editing.id);
    if(dup&&!dupOk){dupOk=true;err.textContent=dupMsg(dup);err.hidden=false;save.disabled=false;save.textContent="Save anyway";return;}
  }
  var oldReceipt=null,oldReceipt2=null;
  try{
    if(pendingBlob&&assets){
      var up=await assets.upload(pendingBlob);
      oldReceipt=e.receiptId||null;e.receiptId=up.id;e.receiptType=pendingType;e.noReceipt=false;
    }
    if(pendingBlob2&&assets){var up2=await assets.upload(pendingBlob2);oldReceipt2=e.receiptId2||null;e.receiptId2=up2.id;}
  }catch(x){err.textContent="The photo couldn't be stored, so nothing was saved. Try again, or remove the photo and save without it.";err.hidden=false;save.disabled=false;save.textContent="Save purchase";return;}
  try{
    await store.saveEntry(e);
    if(oldReceipt&&assets)assets.delete(oldReceipt).catch(function(){});
    if(oldReceipt2&&assets)assets.delete(oldReceipt2).catch(function(){});
    if(S.days[date]&&S.days[date].noSpend)store.setNoSpend(date,false).catch(function(){});
    closeEntry();toast("Saved: "+what+", "+money(e.amount));
  }catch(x){err.textContent=saveErr(x);err.hidden=false;save.disabled=false;save.textContent="Save purchase";}
});
$("f-delete").addEventListener("click",async function(){
  if(!editing)return;
  if(!deleteArmed){deleteArmed=true;this.textContent="Tap again to delete";return;}
  var e=editing;this.disabled=true;
  try{await store.deleteEntry(e.id);if(e.receiptId&&assets)assets.delete(e.receiptId).catch(function(){});if(e.receiptId2&&assets)assets.delete(e.receiptId2).catch(function(){});closeEntry();toast("Deleted.");}
  catch(x){$("f-err").textContent=saveErr(x);$("f-err").hidden=false;}
  this.disabled=false;
});
$("receiptClose").addEventListener("click",closeReceipt);

/* ---------- bill form ---------- */
function openBill(b){
  if(!S.ready)return;
  billEditing=b;billDeleteArmed=false;
  $("billTitle").textContent=b?"Edit bill":"Add a recurring bill";
  $("b-name").value=b?b.name:"";$("b-amount").value=b&&b.amount!=null?(+b.amount).toFixed(2):"";
  $("b-due").value=b?b.dueDay:"";$("b-cat").value=b?(b.category||""):"housing";
  $("b-err").hidden=true;$("b-save").disabled=false;
  var del=$("b-delete");del.hidden=!b;del.textContent="Delete";
  $("billDlg").showModal();
}
$("b-cancel").addEventListener("click",function(){$("billDlg").close();});
$("billForm").addEventListener("submit",async function(ev){
  ev.preventDefault();
  var err=$("b-err"),name=$("b-name").value.trim(),amount=parseFloat($("b-amount").value),due=parseInt($("b-due").value,10);
  var bad=!name?"Name the bill.":!(amount>0)?"Enter the usual amount.":!(due>=1&&due<=31)?"Enter the day of the month it's due, 1 to 31.":"";
  if(bad){err.textContent=bad;err.hidden=false;return;}
  $("b-save").disabled=true;
  try{await store.saveBill({id:billEditing?billEditing.id:undefined,name:name,amount:Math.round(amount*100)/100,dueDay:due,category:$("b-cat").value||"other"});$("billDlg").close();toast("Bill saved.");}
  catch(x){err.textContent=saveErr(x);err.hidden=false;}
  $("b-save").disabled=false;
});
$("b-delete").addEventListener("click",async function(){
  if(!billEditing)return;
  if(!billDeleteArmed){billDeleteArmed=true;this.textContent="Tap again to delete";return;}
  try{await store.deleteBill(billEditing.id);$("billDlg").close();toast("Bill removed. Past payments stay in your log.");}
  catch(x){$("b-err").textContent=saveErr(x);$("b-err").hidden=false;}
});

fillSelect($("f-cat"),CATS,"Choose a category");
fillSelect($("b-cat"),CATS,"Choose a category");
fillSelect($("f-pay"),PAYS.map(function(p){return [p,p];}),"Choose");
/* ---------- search, returns, second photo ---------- */
var pendingBlob2=null;
function daysLeft(s){return Math.round((fromIso(s)-fromIso(today()))/86400000);}
function matches(e,q){
  var hay=[e.what,e.where,e.note,e.bankDesc,CATNAME[e.category],e.receipt&&e.receipt.no,e.date].concat((e.items||[]).map(function(i){return (i.id||"")+" "+(i.name||"");})).join(" ").toLowerCase();
  return q.split(/\s+/).every(function(w){return hay.indexOf(w)>=0;});
}
function viewReturns(v){
  var list=S.entries.filter(function(e){return e.returnBy&&daysLeft(e.returnBy)>=0&&!fullyReturned(e);}).sort(function(a,b){return a.returnBy.localeCompare(b.returnBy);});
  v.append(h("h2",{text:"Still returnable"}));
  var anyList=S.entries.filter(function(e){return e.returnAny&&!fullyReturned(e);}).slice(0,30),backList=S.entries.filter(function(e){return refunded(e)>0;}).slice(0,30);
  if(!list.length&&!anyList.length&&!backList.length){v.append(h("p",{class:"empty",text:"Nothing with an open return window. When you log something you might take back, set its return-by date and it stays here until the deadline passes."}));return;}
  list.forEach(function(e){v.append(h("div",{class:"dayhead"},h("span",{text:"Return by "+dayLabel(e.returnBy)}),h("span",{text:money(e.amount)})));v.append(entryRow(e));});
  if(list.length)v.append(calBtn("Add these deadlines to my calendar",returnEvents(list)));
  if(anyList.length){v.append(h("h2",{text:"Returnable any time"}));anyList.forEach(function(e){v.append(entryRow(e));});}
  if(backList.length){v.append(h("h2",{text:"Returned"}));backList.forEach(function(e){v.append(entryRow(e));});}
}
function setReturn(n){var d=fromIso(parseDate($("f-date").value)||today());d.setDate(d.getDate()+n);$("f-return").value=iso(d);}
$("f-ret30").addEventListener("click",function(){setReturn(30);});
$("f-ret90").addEventListener("click",function(){setReturn(90);});
$("f-ret0").addEventListener("click",function(){$("f-return").value="";});
$("f-receipt2").addEventListener("change",async function(){
  var f=this.files&&this.files[0];if(!f)return;
  if(!/^image\//.test(f.type)||f.size>20*1024*1024){toast("Choose a photo under 20 MB.");this.value="";return;}
  pendingBlob2=await shrink(f);$("f-receipt2Note").textContent="Second photo ready. It saves with the purchase.";
});
$("receiptImg2").addEventListener("click",function(){this.classList.toggle("zoom");});
/* ---------- return windows from store policies ---------- */
/* Standard windows each retailer publishes, checked November 2026. days: a number, "any", or 0 for final sale. elec: shorter window for electronics. */
var POLICIES=[
  {re:/costco/,name:"Costco",days:"any",elec:90,desc:"any time; 90 days for electronics and major appliances"},
  {re:/walmart/,name:"Walmart",days:90,elec:30,desc:"90 days; 30 days for most electronics"},
  {re:/best ?buy/,name:"Best Buy",days:30,desc:"30 days; 15 for phones; longer over the holidays"},
  {re:/amazon|amzn/,name:"Amazon",days:30,holiday:[1,31],desc:"30 days from delivery; November and December orders until January 31"},
  {re:/canadian tire/,name:"Canadian Tire",days:90,elec:30,desc:"90 days unopened; 30 days for electronics"},
  {re:/home depot/,name:"Home Depot",days:90,desc:"90 days; some items shorter"},
  {re:/ikea/,name:"IKEA",days:365,desc:"365 days unopened; 90 days if opened"},
  {re:/winners|marshalls|homesense/,name:"Winners, Marshalls and HomeSense",days:10,desc:"10 days with receipt; 30 for STYLE+ members"},
  {re:/shoppers/,name:"Shoppers Drug Mart",days:30,desc:"30 days, unopened"},
  {re:/sport ?chek/,name:"Sport Chek",days:30,desc:"30 days for a refund; store credit up to 60 days"},
  {re:/\bmark'?s\b/,name:"Mark's",days:100,desc:"100 days, unworn"},
  {re:/staples/,name:"Staples",days:30,elec:14,desc:"30 days; 14 days for computers, tablets and phones"},
  {re:/dollarama/,name:"Dollarama",days:0,desc:"final sale, no returns or exchanges"}
];
var ELEC=/\b(tv|television|laptop|computer|macbook|ipad|tablet|phone|iphone|camera|drone|monitor|headphones?|earbuds?|airpods?|printer|console|playstation|xbox|smart ?watch|projector|appliance|fridge|refrigerator|washer|dryer|dishwasher)\b/i;
var RETURN_CATS=["","shopping","work","fun","other","health"];
var returnTouched=false,returnAuto=false;
function policyFor(where,cat,text,date){
  if(RETURN_CATS.indexOf(cat||"")<0)return null;
  var w=(where||"").toLowerCase(),p=null;
  for(var i=0;i<POLICIES.length;i++)if(POLICIES[i].re.test(w)){p=POLICIES[i];break;}
  if(!p)return null;
  var d=(p.elec!=null&&ELEC.test(text||""))?p.elec:p.days,out={name:p.name,desc:p.desc};
  if(d==="any"){out.any=true;return out;}
  if(d===0){out.none=true;return out;}
  var base=fromIso(parseDate(date)||today()),by=new Date(base);by.setDate(by.getDate()+d);
  if(p.holiday&&base.getMonth()>=10){var hd=new Date(base.getFullYear()+1,p.holiday[0]-1,p.holiday[1]);if(hd>by)by=hd;}
  out.by=iso(by);return out;
}
function suggestReturn(){
  if(returnTouched)return;
  var its=(typeof pendingItems!=="undefined"&&pendingItems)||(editing&&editing.items)||[];
  var text=$("f-what").value+" "+its.map(function(i){return i.name||"";}).join(" ");
  var p=policyFor($("f-where").value,returnCat(),text,$("f-date").value),note=$("f-returnNote");
  if(!p){if(returnAuto){$("f-return").value="";$("f-returnAny").checked=false;returnAuto=false;note.textContent="";}return;}
  $("f-returnAny").checked=!!p.any;$("f-return").value=p.by||"";returnAuto=!p.none;
  note.textContent=p.none?p.name+": "+p.desc+".":"Auto-filled from "+p.name+"'s usual policy ("+p.desc+"). Edit it if your receipt says otherwise.";
}
function touchReturn(){returnTouched=true;returnAuto=false;$("f-returnNote").textContent="";}
["f-where","f-cat","f-date","f-what"].forEach(function(id){$(id).addEventListener("change",suggestReturn);});
["f-ret30","f-ret90","f-ret0"].forEach(function(id){$(id).addEventListener("click",function(){touchReturn();$("f-returnAny").checked=false;});});
$("f-return").addEventListener("input",function(){touchReturn();if(this.value)$("f-returnAny").checked=false;});
$("f-returnAny").addEventListener("change",function(){touchReturn();if(this.checked)$("f-return").value="";});
/* ---------- scan or type chooser ---------- */
var chooseDate=null,autoScan=false,readOk=false,scanSaved=false;
function openChooser(date){
  if(!S.ready){toast("Still connecting. Try again in a moment.");return;}
  chooseDate=date||today();$("scanFile").value="";$("chooseDlg").showModal();
}
$("chooseCancel").addEventListener("click",function(){$("chooseDlg").close();});
$("chooseManual").addEventListener("click",function(){T("purchase_manual");$("chooseDlg").close();openEntry({date:chooseDate});});
$("receiptImg").addEventListener("click",function(){this.classList.toggle("zoom");});
$("scanFile").addEventListener("change",async function(){
  var f=this.files&&this.files[0];if(!f)return;
  $("chooseDlg").close();
  if(!/^image\//.test(f.type)){toast("Choose a photo of the receipt.");return;}
  T("receipt_scan");
  if(f.size>20*1024*1024){toast("That photo is over 20 MB. Choose a smaller one.");return;}
  openEntry({date:chooseDate});
  $("entryTitle").textContent="Reading your receipt on this phone…";
  pendingBlob=await shrink(f);pendingType="image";
  previewUrl=URL.createObjectURL(pendingBlob);
  var p=$("f-preview");p.src=previewUrl;p.hidden=false;
  if(sample&&canReadImages){autoScan=true;readOk=false;$("f-read").hidden=false;$("f-read").click();}
  else{
    $("entryTitle").textContent="Add the details";
    $("f-receiptNote").textContent=assets?"Photo attached. Receipt reading isn't available in this view, so type the details.":"This view can't read or keep the photo. Type the details.";
  }
});

/* ---------- per-item categories ---------- */
function guessItemCat(name){
  var n=(name||"").toLowerCase();
  if(/fries|gravy|hot ?dog|pizza|burger|poutine|combo|latte|coffee|sandwich|sundae|smoothie|chicken bake|\bwrap\b/.test(n))return "eating";
  if(/\bgas\b|fuel|unleaded|diesel|washer fluid|motor oil/.test(n))return "transport";
  if(/polo|jean|pullover|yoga|shirt|\btee\b|sock|jacket|hoodie|sweater|\bpants?\b|shorts|shoe|boot|legging|underwear|glove|\bhat\b|towel|blanket|pillow|\btoy|lego|\bbook|batter(y|ies)|charger|cable|\btv\b|laptop|headphone|\blamp|candle|\bpan\b|knife/.test(n))return "shopping";
  if(/vitamin|tylenol|advil|ibuprofen|bandage|toothpaste|shampoo|\bsoap|lotion|deodorant|razor|sunscreen|allergy/.test(n))return "health";
  if(/mango|orange|pear|apple|banana|berr(y|ies)|grape|lemon|lime|avocado|tomato|marzano|potato|onion|garlic|spinach|\bspin\b|lettuce|kale|carrot|pepper|cucumber|broccoli|organic|milk|cheese|paneer|yogurt|butter|\beggs?\b|bread|pita|\brice\b|flour|sugar|\boil\b|pasta|noodle|chicken|beef|pork|salmon|\bfish|shrimp|coke|pepsi|juice|water|watr|soda|chips|cookie|chocolate|cereal|\boats|\bnuts|almond|salsa|sauce|soup|beans|lentil|\bdal\b|masala|\btea\b/.test(n))return "groceries";
  return "";
}
function catFromLabel(s){
  s=(s||"").trim().toLowerCase();if(!s)return "";
  for(var i=0;i<CATS.length;i++)if(CATS[i][0]===s||CATS[i][1].toLowerCase()===s)return CATS[i][0];
  for(i=0;i<CATS.length;i++)if(CATS[i][1].toLowerCase().indexOf(s)===0)return CATS[i][0];
  return "";
}
/* Fill in a category for each line. A discount line takes the category of the item it refers to, or the line above it. */
function fillItemCats(items){
  items.forEach(function(it,k){
    if(it.cat)return;
    var isDisc=it.cost<0||(it.name||"").charAt(0)==="/";
    if(!isDisc){it.cat=guessItemCat(it.name);return;}
    var ref=((it.name||"").match(/\d{4,}/)||[])[0],hit=ref&&items.filter(function(x){return x.id===ref;})[0];
    it.cat=(hit&&(hit.cat||guessItemCat(hit.name)))||(k>0?items[k-1].cat:"")||"";
  });
  return items;
}
/* Spending per category for a list of purchases. A receipt with categorised lines is split across them, tax shared in proportion. */
function spendByCat(list){
  var by={};
  list.forEach(function(e){
    var amt=+e.amount||0,its=Array.isArray(e.items)?e.items:[],s=its.reduce(function(t,i){return t+(+i.cost||0);},0);
    if(its.length&&s>0&&its.some(function(i){return i.cat;})){
      its.forEach(function(i){var k=i.cat||e.category||"unsorted";by[k]=(by[k]||0)+(+i.cost||0)/s*amt-(i.ret?(+i.ret.amt||0):0);});
    }else{var k=e.category||"unsorted";by[k]=(by[k]||0)+net(e);}
  });
  return by;
}
function returnCat(){
  var c=$("f-cat").value,its=textToItems($("f-items").value);
  if(RETURN_CATS.indexOf(c)>=0)return c;
  return its.some(function(i){return i.cat&&RETURN_CATS.indexOf(i.cat)>0;})?"shopping":c;
}

/* ---------- sharing a file out of the app ---------- */
async function shareOrDownload(blob,name){
  try{
    var f=new File([blob],name,{type:blob.type});
    if(navigator.canShare&&navigator.canShare({files:[f]})){await navigator.share({files:[f],title:name});return;}
  }catch(e){if(e&&e.name==="AbortError")return;}
  var url=URL.createObjectURL(blob),a=h("a",{href:url,download:name});
  document.body.append(a);a.click();a.remove();
  setTimeout(function(){URL.revokeObjectURL(url);},60000);
}

/* ---------- full backup: everything including receipt photos, encrypted with a backup password ---------- */
var BACKUP_MAGIC="SPENDLOG-BACKUP-1\n",lockedBackup=null;
function fullBackupUI(){
  var msg=h("p",{class:"err",role:"alert",hidden:true});
  var btn=h("button",{type:"button",class:"btn",text:"Save full backup with photos",onclick:async function(){
    var p=$("s-bpass").value;
    if(p.length<6){msg.textContent="Choose a backup password of at least 6 characters.";msg.hidden=false;return;}
    msg.hidden=true;btn.disabled=true;btn.textContent="Packing the backup…";
    try{await saveFullBackup(p);$("s-bpass").value="";}
    catch(e){msg.textContent="The backup couldn't be made. If you have many photos, free up memory by closing other apps and try again.";msg.hidden=false;}
    btn.disabled=false;btn.textContent="Save full backup with photos";
  }});
  return h("div",{class:"field"},
    h("p",{class:"small muted",text:"Full backup: every purchase, bill and receipt photo in one file, encrypted with a password you choose here. It can be different from your passcode. Without that password the file can't be opened by anyone, including you."}),
    pwField("s-bpass","Backup password","new-password"),msg,h("div",{class:"btnrow"},btn));
}
async function saveFullBackup(pass){
  var ids=await recKeys(),metas=[],parts=[],off=0,i;
  for(i=0;i<ids.length;i++){
    var rec=await recGet(ids[i]);if(!rec)continue;
    var bytes=await unseal(DEK,rec);
    metas.push({id:ids[i],type:rec.type||"image/jpeg",off:off,len:bytes.length});parts.push(bytes);off+=bytes.length;
  }
  var meta=new TextEncoder().encode(JSON.stringify({app:"spendlog",v:2,exportedAt:new Date().toISOString(),entries:S.entries,bills:S.bills,days:S.days,receipts:metas}));
  var plain=new Uint8Array(4+meta.length+off);new DataView(plain.buffer).setUint32(0,meta.length);
  plain.set(meta,4);var at=4+meta.length;parts.forEach(function(b){plain.set(b,at);at+=b.length;});
  var salt=rnd(16),box=await seal(await kek(pass,salt,ITER),plain);
  await shareOrDownload(new Blob([new TextEncoder().encode(BACKUP_MAGIC),salt,box.iv,box.ct],{type:"application/octet-stream"}),"spend-log-full-backup-"+today()+".spendlog");
}
async function openBackupFile(f){
  var buf=new Uint8Array(await f.arrayBuffer()),m=new TextEncoder().encode(BACKUP_MAGIC),isFull=buf.length>m.length+28;
  for(var i=0;isFull&&i<m.length;i++)if(buf[i]!==m[i])isFull=false;
  if(isFull){lockedBackup=buf.slice(m.length);pendingRestore=null;render();return;}
  var d=JSON.parse(new TextDecoder().decode(buf));
  if(!d||d.app!=="spendlog"||!Array.isArray(d.entries))throw new Error("bad");
  lockedBackup=null;pendingRestore=d;render();
}
function unlockBackupUI(){
  var msg=h("p",{class:"err",role:"alert",hidden:true});
  var btn=h("button",{type:"button",class:"btn",text:"Open this backup",onclick:async function(){
    btn.disabled=true;btn.textContent="Opening…";
    try{
      var b=lockedBackup,plain=await unseal(await kek($("s-upass").value,b.slice(0,16),ITER),{iv:b.slice(16,28),ct:b.slice(28)});
      var n=new DataView(plain.buffer,plain.byteOffset).getUint32(0),d=JSON.parse(new TextDecoder().decode(plain.slice(4,4+n))),body=plain.subarray(4+n);
      if(!d||d.app!=="spendlog"||!Array.isArray(d.entries))throw new Error("bad");
      d.receipts=(d.receipts||[]).map(function(r){return {id:r.id,type:r.type,bytes:body.slice(r.off,r.off+r.len)};});
      lockedBackup=null;pendingRestore=d;render();
    }catch(e){msg.textContent="That password doesn't open this backup.";msg.hidden=false;btn.disabled=false;btn.textContent="Open this backup";}
  }});
  return h("div",{class:"field"},h("p",{class:"small",style:"font-weight:600",text:"This is a full backup. Enter its backup password."}),pwField("s-upass","Backup password","current-password"),msg,
    h("div",{class:"btnrow"},btn,h("button",{type:"button",class:"btn quiet",text:"Cancel",onclick:function(){lockedBackup=null;render();}})));
}
async function restoreReceipts(d){
  if(!d.receipts)return;
  for(var i=0;i<d.receipts.length;i++){var r=d.receipts[i],box=await seal(DEK,r.bytes);await recSet(r.id,{iv:box.iv,ct:box.ct,type:r.type});}
}

/* ---------- calendar reminders (.ics file the phone's calendar can import) ---------- */
function icsText(s){return String(s||"").replace(/\\/g,"\\\\").replace(/[,;]/g,function(c){return "\\"+c;}).replace(/\r?\n/g,"\\n");}
function icsDay(s){return s.replace(/-/g,"");}
function nextDay(s){var d=fromIso(s);d.setDate(d.getDate()+1);return iso(d);}
function makeIcs(events){
  var stamp=new Date().toISOString().replace(/[-:]/g,"").replace(/\.\d+/,""),L=["BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//Spend Log//EN","CALSCALE:GREGORIAN"];
  events.forEach(function(ev){
    L.push("BEGIN:VEVENT","UID:"+ev.uid+"@spend-log","DTSTAMP:"+stamp,"DTSTART;VALUE=DATE:"+icsDay(ev.date),"DTEND;VALUE=DATE:"+icsDay(nextDay(ev.date)),"SUMMARY:"+icsText(ev.summary));
    if(ev.desc)L.push("DESCRIPTION:"+icsText(ev.desc));
    if(ev.rrule)L.push("RRULE:"+ev.rrule);
    L.push("TRANSP:TRANSPARENT","BEGIN:VALARM","ACTION:DISPLAY","DESCRIPTION:"+icsText(ev.summary),"TRIGGER:-P"+(ev.alarmDays||1)+"D","END:VALARM","END:VEVENT");
  });
  L.push("END:VCALENDAR");return L.join("\r\n")+"\r\n";
}
function returnEvents(list){
  return list.map(function(e){return {uid:"return-"+e.id,date:e.returnBy,summary:"Last day to return: "+title(e),desc:(e.where?e.where+". ":"")+"Paid "+money(e.amount)+" on "+dayLabel(e.date)+". The receipt is in Spend Log.",alarmDays:2};});
}
function billEvents(){
  var t=new Date();
  return S.bills.map(function(b){
    var day=Math.min(b.dueDay||1,28),d=new Date(t.getFullYear(),t.getMonth(),day);if(iso(d)<today())d=new Date(t.getFullYear(),t.getMonth()+1,day);
    return {uid:"bill-"+b.id,date:iso(d),summary:b.name+" due ("+money(b.amount)+")",rrule:(b.dueDay||1)>28?"FREQ=MONTHLY;BYMONTHDAY=-1":"FREQ=MONTHLY;BYMONTHDAY="+day,alarmDays:1,
      date2:null};
  }).map(function(ev,k){var b=S.bills[k];if((b.dueDay||1)>28){var n=new Date(t.getFullYear(),t.getMonth()+1,0);if(iso(n)<today())n=new Date(t.getFullYear(),t.getMonth()+2,0);ev.date=iso(n);}delete ev.date2;return ev;});
}
function calBtn(label,events){
  return h("div",{class:"btnrow"},h("button",{type:"button",class:"btn quiet",text:label,onclick:function(){
    shareOrDownload(new Blob([makeIcs(events)],{type:"text/calendar"}),"spend-log-reminders.ics");
  }}));
}

/* ---------- returns and refunds ---------- */
function refunded(e){
  var t=e.ret?(+e.ret.amt||0):0;
  (e.items||[]).forEach(function(i){if(i.ret)t+=(+i.ret.amt||0);});
  return Math.round(t*100)/100;
}
function net(e){return Math.round(((+e.amount||0)-refunded(e))*100)/100;}
function fullyReturned(e){
  if(e.ret)return true;
  var its=(e.items||[]).filter(function(i){return (+i.cost||0)>0;});
  return its.length>0&&its.every(function(i){return i.ret;});
}
/* Suggested refund for one line: its price, less any discount line that points at it, plus its share of the tax. */
function itemShare(e,k){
  var its=e.items,it=its[k],s=its.reduce(function(t,i){return t+(+i.cost||0);},0),base=+it.cost||0;
  its.forEach(function(x){if((+x.cost||0)<0&&it.id&&(x.name||"").indexOf(it.id)>=0)base+=(+x.cost||0);});
  return s>0?Math.round(base/s*(+e.amount||0)*100)/100:Math.round(base*100)/100;
}
function keepReturns(items,old){
  (old||[]).forEach(function(o){
    if(!o.ret)return;
    var m=items.filter(function(i){return !i.ret&&((o.id&&i.id===o.id)||(!o.id&&i.name===o.name));})[0];
    if(m)m.ret=o.ret;
  });
}
function retBtn(e,it,k){
  if(it.ret)return h("button",{type:"button",class:"chip need",text:"Returned −"+money(it.ret.amt),"aria-label":"Returned "+(it.name||"item")+". Change or undo.",onclick:function(){openReturn(e,k);}});
  if((+it.cost||0)>0)return h("button",{type:"button",class:"chip","aria-label":"Mark "+(it.name||"item")+" as returned",text:"Return",onclick:function(){openReturn(e,k);}});
  return null;
}
var retCtx=null;
function openReturn(e,k){
  if(!DEK)return;
  retCtx={id:e.id,k:k};
  var hasItems=Array.isArray(e.items)&&e.items.length>0,it=k>=0?e.items[k]:null,cur=it?it.ret:e.ret;
  $("retTitle").textContent=cur?"Returned":"Mark as returned";
  $("r-what").textContent=it?(it.id?it.id+"  ":"")+(it.name||"Item")+", from "+title(e):(hasItems?"Everything still unreturned on this receipt: ":"")+title(e);
  $("r-amt").value=(cur?+cur.amt:(it?itemShare(e,k):net(e))).toFixed(2);
  $("r-date").value=cur?cur.d:today();
  $("r-note").textContent=it?"The refund is pre-filled with the item's price, less its discount, plus its share of the tax. Change it to what the store gave back.":"The refund is pre-filled with what you paid. Change it to what the store gave back.";
  $("r-err").hidden=true;$("r-undo").hidden=!cur;$("r-save").disabled=false;$("r-save").textContent=cur?"Save changes":"Mark as returned";
  $("retDlg").showModal();
}
async function saveReturn(undo){
  var e=S.entries.filter(function(x){return x.id===retCtx.id;})[0],err=$("r-err");if(!e)return;
  var c=clean(e),k=retCtx.k,amt=Math.round(parseFloat($("r-amt").value)*100)/100,d=$("r-date").value,hasItems=Array.isArray(c.items)&&c.items.length>0;
  if(!undo){
    var room=(+e.amount||0)-refunded(e)+(k>=0&&e.items[k].ret?+e.items[k].ret.amt:0)+(k<0&&e.ret?+e.ret.amt:0);
    var bad=!(amt>=0)?"Enter the refund amount.":amt>room+0.005?"That is more than you paid. The most this can be is "+money(room)+".":!parseDate(d)?"Pick the date you returned it.":d>today()?"That date is in the future.":"";
    if(bad){err.textContent=bad;err.hidden=false;return;}
  }
  if(k>=0){if(undo)delete c.items[k].ret;else c.items[k].ret={d:d,amt:amt};}
  else if(hasItems){
    /* Spread the refund so every category ends at what was really kept: each category's remaining spend
       (its lines' share of the bill, discounts included, less earlier refunds) goes to its unreturned items. */
    var sAll=c.items.reduce(function(t,i){return t+(+i.cost||0);},0),rem={},pool={},idx=[],first=null,left=net(e);
    var catOf=function(i){return i.cat||c.category||"unsorted";};
    c.items.forEach(function(i,j){
      var kc=catOf(i);rem[kc]=(rem[kc]||0)+(sAll>0?(+i.cost||0)/sAll*(+c.amount||0):0)-(i.ret?(+i.ret.amt||0):0);
      if((+i.cost||0)>0&&!i.ret){idx.push(j);pool[kc]=(pool[kc]||0)+(+i.cost||0);if(first==null)first=kc;}
    });
    Object.keys(rem).forEach(function(kc){if(!pool[kc]&&first!=null){rem[first]=(rem[first]||0)+rem[kc];rem[kc]=0;}});
    var scale=left>0?amt/left:0,given=0;
    idx.forEach(function(j,n){
      var i=c.items[j],kc=catOf(i),v=Math.round(rem[kc]*scale*(+i.cost||0)/pool[kc]*100)/100;
      if(n===idx.length-1)v=Math.round((amt-given)*100)/100;
      given+=v;i.ret={d:d,amt:v};
    });
  }else{if(undo)delete c.ret;else c.ret={d:d,amt:amt};}
  $("r-save").disabled=true;
  try{await store.saveEntry(c);$("retDlg").close();toast(undo?"Return undone.":"Marked as returned. "+money(amt)+" taken off your spending.");}
  catch(x){err.textContent=saveErr(x);err.hidden=false;$("r-save").disabled=false;}
}
$("retForm").addEventListener("submit",function(ev){ev.preventDefault();saveReturn(false);});
$("r-undo").addEventListener("click",function(){saveReturn(true);});
$("r-cancel").addEventListener("click",function(){$("retDlg").close();});

/* ---------- lock, backup, settings ---------- */
var lockMode="unlock",eraseArmed=false,pendingRestore=null,settingsEraseArmed=false;
function pwField(id,label,auto){return h("div",{class:"field"},h("label",{for:id,text:label}),h("input",{type:"password",id:id,autocomplete:auto,autocapitalize:"off",autocorrect:"off",spellcheck:"false"}));}

function viewSettings(v){
  v.append(h("h2",{text:"Account, lock & backup"}));
  v.append(cloudPanel());
  v.append(h("p",{class:"muted",text:keepOn?"Everything you log is encrypted and kept on this phone only. After you enter the passcode once, this phone stays unlocked. Your phone's own lock is what protects it. Tap Lock now to ask for the passcode again.":"Everything you log is encrypted and kept on this phone only. The app asks for the passcode every time you open it, and after 3 minutes in the background."}));
  var every=h("input",{type:"checkbox",id:"s-every"});every.checked=!keepOn;
  every.addEventListener("change",function(){keepOn=!every.checked;kvSet("keep",keepOn).then(function(){return kvSet("dek",keepOn?DEK:null);}).catch(function(){});render();});
  v.append(h("label",{class:"check",for:"s-every"},every,"Ask for my passcode every time I open the app"));
  v.append(h("div",{class:"btnrow"},h("button",{type:"button",class:"btn",text:"Lock now",onclick:lock})));

  if(vaultKind==="pixora")v.append(pxPassPanel());
  var msg=h("p",{class:"err",role:"alert",hidden:true});
  var change=h("button",{type:"button",class:"btn",text:"Change passcode",onclick:async function(){
    var cur=$("s-cur").value,nw=$("s-new").value,cf=$("s-conf").value;
    var bad=nw.length<4?"Use at least 4 characters. Six or more is much harder to guess.":nw!==cf?"The two new passcodes don't match.":"";
    if(bad){msg.textContent=bad;msg.hidden=false;return;}
    change.disabled=true;change.textContent="Changing…";
    try{await changePass(cur,nw);toast("Passcode changed.");render();}
    catch(e){msg.textContent="The current passcode is wrong.";msg.hidden=false;change.disabled=false;change.textContent="Change passcode";}
  }});
  if(vaultKind!=="pixora")v.append(h("div",{class:"panel"},h("h3",{text:"Passcode"}),h("p",{class:"small muted",text:"This phone uses its own Spend Log passcode. Sign in to a Pixora account to switch to your one Pixora passcode."}),pwField("s-cur","Current passcode","current-password"),pwField("s-new","New passcode","new-password"),pwField("s-conf","Repeat new passcode","new-password"),msg,h("div",{class:"btnrow"},change)));

  var file=h("input",{type:"file",id:"s-restore",accept:".json,.spendlog,application/json,application/octet-stream","aria-label":"Backup file to restore"});
  file.addEventListener("change",function(){
    var f=file.files&&file.files[0];if(!f)return;
    openBackupFile(f).catch(function(){toast("That isn't a Spend Log backup file.");file.value="";});
  });
  var backup=h("div",{class:"panel"},h("h3",{text:"Backup"}),
    h("p",{class:"small muted",text:"A forgotten passcode can't be recovered, and a lost phone takes the data with it. A backup file is the only way back. Save one to iCloud Drive or email it to yourself."}),
    fullBackupUI(),
    h("p",{class:"small muted",text:"Quick backup: purchases and bills only, no photos, not encrypted. Keep it somewhere private."}),
    h("div",{class:"btnrow"},h("button",{type:"button",class:"btn quiet",text:"Save a quick backup",onclick:saveBackup})),
    h("div",{class:"field"},h("label",{for:"s-restore",text:"Restore from a backup file"}),file));
  if(lockedBackup)backup.append(unlockBackupUI());
  if(pendingRestore){
    backup.append(h("p",{class:"small",style:"font-weight:600",text:"This backup holds "+pendingRestore.entries.length+" purchases, "+((pendingRestore.bills||[]).length)+" bills and "+((pendingRestore.receipts||[]).length)+" receipt photos. Restoring replaces everything on this phone."}),
      h("div",{class:"btnrow"},
        h("button",{type:"button",class:"btn danger",text:"Replace with this backup",onclick:doRestore}),
        h("button",{type:"button",class:"btn quiet",text:"Cancel",onclick:function(){pendingRestore=null;render();}})));
  }
  v.append(backup);

  var erase=h("button",{type:"button",class:"btn danger",text:settingsEraseArmed?"Tap again to erase everything":"Erase all data on this phone",onclick:async function(){
    if(!settingsEraseArmed){settingsEraseArmed=true;render();return;}
    settingsEraseArmed=false;await eraseEverything();
  }});
  v.append(h("div",{class:"panel"},h("h3",{text:"Start over"}),h("p",{class:"small muted",text:"Deletes every purchase, bill, receipt photo and the passcode from this phone, and the Spend Log data in your Pixora account if you are signed in. Your Pixora login is not deleted. To delete the login itself, email pixora3dstudios@gmail.com."}),h("div",{class:"btnrow"},erase)));
}
async function saveBackup(){
  var json=JSON.stringify({app:"spendlog",v:1,exportedAt:new Date().toISOString(),entries:S.entries,bills:S.bills,days:S.days});
  var name="spend-log-backup-"+today()+".json";
  try{
    var f=new File([json],name,{type:"application/json"});
    if(navigator.canShare&&navigator.canShare({files:[f]})){await navigator.share({files:[f],title:"Spend Log backup"});return;}
  }catch(e){if(e&&e.name==="AbortError")return;}
  var url=URL.createObjectURL(new Blob([json],{type:"application/json"}));
  var a=h("a",{href:url,download:name});document.body.append(a);a.click();a.remove();
  setTimeout(function(){URL.revokeObjectURL(url);},30000);
}
async function doRestore(){
  var d=pendingRestore;if(!d)return;pendingRestore=null;
  try{
    await restoreReceipts(d);
    var keys={};(await recKeys()).forEach(function(k){keys[k]=1;});
    var now1=Date.now();S.tomb=S.tomb||{};S.entries.forEach(function(e){S.tomb["e_"+e.id]=now1;});S.bills.forEach(function(b){S.tomb["b_"+b.id]=now1;});
    S.entries=sortEntries(d.entries.map(function(e){e=Object.assign({},e);if(e.receiptId&&!keys[e.receiptId]){delete e.receiptId;delete e.receiptType;}if(e.receiptId2&&!keys[e.receiptId2])delete e.receiptId2;return e;}));
    S.bills=Array.isArray(d.bills)?d.bills:[];S.days=d.days&&typeof d.days==="object"?d.days:{};
    var now2=Date.now()+1;S.entries.forEach(function(e){e.ts=now2;delete S.tomb["e_"+e.id];});S.bills.forEach(function(b){b.ts=now2;delete S.tomb["b_"+b.id];});S.daysTs=now2;S.seen={};
    await persist();toast("Backup restored.");S.tab="log";
  }catch(e){toast(saveErr(e));}
  render();
}
async function eraseEverything(){
  cloudStop();
  if(cuser){try{await cloudWipe();}catch(e){}}
  DEK=null;S.entries=[];S.bills=[];S.days={};S.tomb={};S.seen={};S.daysTs=0;S.ready=false;
  try{await wipeAll();}catch(e){}
  pxNeed=null;cloudConflict=null;vaultKind="legacy";
  if(cuser)await routeSignedIn();else showAccount();
}

function showLock(mode,problem,src){
  lockMode=mode;eraseArmed=false;pxArm=false;$("acct").hidden=true;
  if(mode!=="pxset"&&mode!=="pxunlock")pxCtx=null;
  if(src&&src.startOver)pxCtx=Object.assign({},pxCtx||{},{startOver:true,fromCloud:true});
  var px=mode==="pxset"||mode==="pxunlock",set=mode==="setup"||mode==="pxset";
  $("app").hidden=true;$("lock").hidden=false;var nb=$("navbar");if(nb)nb.hidden=true;
  $("lockTitle").textContent=mode==="pxset"?"Set your Pixora passcode":mode==="pxunlock"?"Enter your Pixora passcode":set?"Set a passcode":"Enter your passcode";
  $("lockSub").textContent=mode==="pxset"?((pxCtx&&pxCtx.startOver)?"A new Pixora passcode for all your Pixora apps. Each app asks for it once. Spend Log starts fresh here; a phone where Spend Log is still open will put its data back.":"One passcode for Spend Log and your other Pixora apps. It locks the key that encrypts your data before it leaves the phone. You type it once per phone, and it can't be recovered, so pick one you'll remember.")
    :mode==="pxunlock"?((pxCtx&&pxCtx.fromCloud)?"Signed in. Enter the passcode you use in your other Pixora apps. This phone remembers it after this.":"The same passcode you use in your other Pixora apps.")
    :set?"It encrypts everything you log on this phone. It can't be recovered if you forget it, so pick one you'll remember. Six or more characters is much harder to guess.":"Your spending is encrypted on this phone.";
  if(src==="cloud"&&!px)$("lockSub").textContent=set?"Signed in. Now set a passcode. It encrypts everything before it reaches your Pixora account, so nobody else can read it.":"Signed in. Enter the Spend Log passcode you set on your other phone. After this, Spend Log moves to your Pixora passcode.";
  $("l-passLabel").textContent=px?"Pixora passcode":"Passcode";
  $("l-confirmField").hidden=!set;
  $("l-pass").value="";$("l-confirm").value="";
  $("l-pass").setAttribute("autocomplete",set?"new-password":"current-password");
  $("l-go").textContent=set?"Set passcode":"Unlock";$("l-go").disabled=!!problem;
  var er=$("l-err");er.hidden=!problem;er.textContent=problem||"";
  var x=$("l-erase");x.hidden=set;x.textContent=px?"Forgot it? Start over":"Forgot it? Erase everything and start over";
  $("l-acct").hidden=!(mode==="setup"&&!cuser&&src!=="cloud");
  $("l-other").hidden=!(px&&cuser);
  if(!problem)try{$("l-pass").focus();}catch(e){}
}
$("l-acct").addEventListener("click",function(){showAccount();});
function lock(){
  if(!DEK)return;
  kvSet("dek",null).catch(function(){});
  cloudStop();
  DEK=null;S.entries=[];S.bills=[];S.days={};S.tomb={};S.seen={};S.daysTs=0;S.ready=false;pendingRestore=null;lockedBackup=null;settingsEraseArmed=false;
  closeEntry();closeReceipt();if($("chooseDlg").open)$("chooseDlg").close();if($("retDlg").open)$("retDlg").close();if($("billDlg").open)$("billDlg").close();
  $("view").textContent="";$("tape").textContent="";$("checkin").textContent="";
  showLock(vaultKind==="pixora"?"pxunlock":"unlock");
}
$("lockForm").addEventListener("submit",async function(ev){
  ev.preventDefault();
  var pass=$("l-pass").value,er=$("l-err"),go=$("l-go");
  var setting=lockMode==="setup"||lockMode==="pxset";
  function fail(m){er.textContent=m;er.hidden=false;go.disabled=false;go.textContent=setting?"Set passcode":"Unlock";}
  er.hidden=true;go.disabled=true;go.textContent=setting?"Setting up…":"Unlocking…";
  if(lockMode==="pxset"||lockMode==="pxunlock"){
    var f0=(await kvGet("fails"))||{n:0,until:0};
    if(lockMode==="pxunlock"&&Date.now()<f0.until)return fail("Too many wrong tries. Wait "+Math.ceil((f0.until-Date.now())/1000)+" seconds.");
    try{await pxLockSubmit(pass,$("l-confirm").value);}
    catch(e){
      if(e&&e.wrong){f0.n++;if(f0.n>=5)f0.until=Date.now()+Math.min(900,30*Math.pow(2,f0.n-5))*1000;await kvSet("fails",f0);return fail(f0.n>=5?"That isn't your Pixora passcode. Wait "+Math.ceil((f0.until-Date.now())/1000)+" seconds before trying again.":"That isn't your Pixora passcode.");}
      return fail((e&&e.msg)||"Something went wrong. Check the connection and try again.");
    }
    await kvSet("fails",{n:0,until:0});pxCtx=null;
    $("l-pass").value="";$("l-confirm").value="";go.disabled=false;
    await rememberKey();enterApp();return;
  }
  try{
    if(lockMode==="setup"){
      if(pass.length<4)return fail("Use at least 4 characters.");
      if(pass!==$("l-confirm").value)return fail("The two passcodes don't match.");
      await createVault(pass);
    }else{
      var f=(await kvGet("fails"))||{n:0,until:0};
      if(Date.now()<f.until)return fail("Too many wrong tries. Wait "+Math.ceil((f.until-Date.now())/1000)+" seconds.");
      try{await openVault(pass);}
      catch(e){
        f.n++;if(f.n>=5)f.until=Date.now()+Math.min(900,30*Math.pow(2,f.n-5))*1000;
        await kvSet("fails",f);
        return fail(f.n>=5?"Wrong passcode. Wait "+Math.ceil((f.until-Date.now())/1000)+" seconds before trying again.":"Wrong passcode.");
      }
      await kvSet("fails",{n:0,until:0});
    }
  }catch(e){return fail("Couldn't open storage on this phone. Close the app and try again.");}
  $("l-pass").value="";$("l-confirm").value="";go.disabled=false;
  await rememberKey();enterApp();
});
/* Staying unlocked: after one correct passcode the data key is kept on this phone in a form that
   web pages cannot read out or copy, so the app opens without asking. "Lock now" removes it. */
var keepOn=true;
async function rememberKey(){
  try{keepOn=(await kvGet("keep"))!==false;await kvSet("dek",keepOn?DEK:null);}catch(e){}
}
async function openWithKey(key){
  var box=await kvGet("state"),data={};
  if(box)data=JSON.parse(new TextDecoder().decode(await unseal(key,box)));
  DEK=key;S.entries=sortEntries(data.entries||[]);S.bills=data.bills||[];S.days=data.days||{};S.daysTs=data.daysTs||0;S.tomb=data.tomb||{};S.seen=data.seen||{};
}
function enterApp(){
  S.ready=true;S.tab="log";S.month=ym(today());
  $("lock").hidden=true;$("acct").hidden=true;$("app").hidden=false;
  render();
  cloudInit().then(function(){paintCloud();if(cuser)cloudStart();});
  try{if(navigator.storage&&navigator.storage.persist)navigator.storage.persist();}catch(e){}
}
$("l-erase").addEventListener("click",async function(){
  if(lockMode==="pxunlock"){
    if(!eraseArmed){eraseArmed=true;this.textContent="Tap again: new Pixora passcode for all your Pixora apps. Spend Log starts over here; a phone where it's still open puts its data back.";return;}
    if(!cuser){await cloudInit();}
    if(!cuser){$("l-err").textContent="Sign in first: connect to the internet and reopen Spend Log.";$("l-err").hidden=false;return;}
    showLock("pxset",null,{startOver:true});return;
  }
  if(!eraseArmed){eraseArmed=true;this.textContent="Tap again: this deletes every purchase and receipt";return;}
  await eraseEverything();
});
$("l-other").addEventListener("click",async function(){
  try{cloudStop();await firebase.auth().signOut();}catch(e){}
  cuser=null;DEK=null;try{await wipeAll();}catch(e){}
  showAccount();
});
document.addEventListener("visibilitychange",function(){
  if(document.hidden)hiddenAt=Date.now();
  else if(DEK&&!keepOn&&hiddenAt&&Date.now()-hiddenAt>180000)lock();
});

fillSelect($("f-cat"),CATS,"Choose a category");
fillSelect($("b-cat"),CATS,"Choose a category");
fillSelect($("f-pay"),PAYS.map(function(p){return [p,p];}),"Choose");

/* ---------- Pixora account and cloud sync ----------
   Firebase project "Pixora" (pixora-bca1f), web app "Spend Log". Each person's data lives under
   apps/spendlog/users/<their uid>, which the database rules let only that person read or write.
   Every record and receipt photo is encrypted on the phone with the Spend Log data key before it
   is uploaded, so the database only ever holds ciphertext: nobody with database access, the
   project owner included, can read it. The data key itself is stored only wrapped by the passcode. */
var CLOUD_ROOT="apps/spendlog/users/",PHOTO_CHUNK=900000;
var fdb=null,cuser=null,authReady=null,cloudUnsub=null,cloudLive=false,cloudState="off",cloudConflict=null,cloudErr="",lastSync=0;
var pushing=false,pushAgain=false,pushTimer=null,photoBusy=false;
function u8(b){return b instanceof Uint8Array?b:new Uint8Array(b);}
function toBytes(u){return firebase.firestore.Blob.fromUint8Array(u8(u));}
function fromBytes(b){return b&&b.toUint8Array?b.toUint8Array():new Uint8Array(0);}
function sts(){return firebase.firestore.FieldValue.serverTimestamp();}
function cloudInit(){
  if(authReady)return authReady;
  authReady=new Promise(function(res){
    if(!window.firebase||!window.PIXORA_CLOUD){res(null);return;}
    try{
      firebase.initializeApp(window.PIXORA_CLOUD);
      fdb=firebase.firestore();
      if(window.PIXORA_EMULATOR){fdb.useEmulator("127.0.0.1",window.PIXORA_EMULATOR.db);firebase.auth().useEmulator("http://127.0.0.1:"+window.PIXORA_EMULATOR.auth,{disableWarnings:true});}
      fdb.enablePersistence({synchronizeTabs:true}).catch(function(){});
    }catch(e){fdb=null;res(null);return;}
    var first=true,t=setTimeout(function(){if(first){first=false;res(cuser);}},6000);
    firebase.auth().onAuthStateChanged(function(u){
      var was=cuser&&cuser.uid;cuser=u||null;
      if(first){first=false;clearTimeout(t);res(cuser);return;}
      if((u&&u.uid)===was)return;
      cloudStop();if(u&&DEK)cloudStart();
      if(S.ready)render();
    });
  });
  return authReady;
}
function userDoc(){return fdb.doc(CLOUD_ROOT+cuser.uid);}
function itemsCol(){return userDoc().collection("items");}
function photosCol(){return userDoc().collection("photos");}
function metaToCloud(m){return {v:1,vid:m.vid,iter:m.iter,salt:toBytes(m.salt),wiv:toBytes(m.wrapped.iv),wct:toBytes(m.wrapped.ct),mts:m.mts||0};}
function metaFromCloud(d){return {v:1,vid:d.vid,iter:d.iter,salt:fromBytes(d.salt),wrapped:{iv:fromBytes(d.wiv),ct:fromBytes(d.wct)},mts:d.mts||0,ph:Array.isArray(d.ph)?d.ph:[]};}
async function getCloudMeta(){var s=await userDoc().get();return s.exists&&s.data().vid?metaFromCloud(s.data()):null;}
function setCloud(state,err){cloudState=state;cloudErr=err||"";if(state==="synced")lastSync=Date.now();paintCloud();}
function paintCloud(){
  var st=$("saveStatus");if(!st)return;
  var txt=!cuser?"On this phone only · Sign in to back up":cloudState==="synced"?"Synced to your Pixora account":cloudState==="syncing"?"Syncing…":cloudState==="offline"?"Offline · will sync later":cloudState==="conflict"?"Account needs your other passcode":cloudState==="error"?"Sync paused":"Connecting to your account…";
  st.textContent=txt;st.className="status"+((!cuser||cloudState==="conflict"||cloudState==="error")?" warn":"");
}
function stampMissing(){
  var ch=false;
  S.entries.forEach(function(e){if(!e.ts){e.ts=1;ch=true;}});
  S.bills.forEach(function(b){if(!b.ts){b.ts=1;ch=true;}});
  if(!S.daysTs&&Object.keys(S.days||{}).length){S.daysTs=1;ch=true;}
  return ch;
}
async function cloudStart(){
  if(!fdb||!cuser||!DEK)return;
  cloudStop();setCloud("syncing");
  var uid=cuser.uid,meta=await kvGet("meta");
  if(!meta.vid){meta.vid=rid();meta.mts=Date.now();await kvSet("meta",meta);}
  vaultKind=meta.kind==="pixora"?"pixora":"legacy";
  var raw;
  try{var snap=await userDoc().get();raw=snap.exists&&snap.data().vid?snap.data():null;}catch(e){setCloud("offline");return;}
  if(!cuser||cuser.uid!==uid||!DEK)return;
  if(!raw){
    try{
      if(vaultKind==="pixora")await userDoc().set({v:2,vid:meta.vid,pk:pkToCloud(await kvGet("pk")),mts:meta.mts||Date.now(),at:sts(),ph:[]});
      else await userDoc().set(Object.assign(metaToCloud(meta),{at:sts(),ph:[]}));
    }catch(e){setCloud("offline");return;}
    raw={vid:meta.vid,mts:meta.mts,ph:[]};if(vaultKind==="legacy")Object.assign(raw,metaToCloud(meta));
  }
  if(raw.vid!==meta.vid){
    cloudConflict=raw.pk?{kind:"pixora",raw:raw}:{kind:"legacy",meta:metaFromCloud(raw)};
    setCloud("conflict");if(S.ready)render();return;
  }
  cloudConflict=null;
  if(Array.isArray(raw.ph)&&raw.ph.length)photoCleanup(raw.ph).catch(function(){});
  if(vaultKind==="legacy"){
    var cm=metaFromCloud(raw);delete cm.ph;
    if((cm.mts||0)>(meta.mts||0))await kvSet("meta",cm);
    else if((meta.mts||0)>(cm.mts||0))userDoc().set(metaToCloud(meta),{merge:true}).catch(function(){});
    if(!pxNeed){pxNeed={why:"migrate"};pxNeedLoad();}
  }else pxCheck(uid).catch(function(){});
  if(stampMissing())await persist();
  cloudLive=true;cloudListen(uid);cloudKick(0);dashKick(1500);
}

/* ---------- Pixora Today dashboard ----------
   A short summary, encrypted on this phone to your own dashboard's key (see pixora-summary.js).
   Only your dashboard can open it. Nothing is sent when you're not signed in or have no dashboard. */
function billDue(b,base){
  var y=base.getFullYear(),m=base.getMonth(),last=new Date(y,m+1,0).getDate();
  return iso(new Date(y,m,Math.min(b.dueDay||1,last)));
}
function dashSummary(){
  var t=today(),m=ym(t),now=new Date(),dom=now.getDate(),lm=shiftMonth(m,-1);
  var inMonth=S.entries.filter(function(e){return !e.needsDetails&&ym(e.date||"")===m;});
  var lastSoFar=S.entries.filter(function(e){return !e.needsDetails&&ym(e.date||"")===lm&&+(e.date||"").slice(8,10)<=dom;});
  var byCat={};inMonth.forEach(function(e){var c=CATNAME[e.category]||"Other";byCat[c]=(byCat[c]||0)+net(e);});
  var top=Object.keys(byCat).map(function(k){return [k,Math.round(byCat[k]*100)/100];}).filter(function(x){return x[1]>0;}).sort(function(a,b){return b[1]-a[1];}).slice(0,3);
  var paidOf=function(b){return S.entries.some(function(e){return e.billId===b.id&&ym(e.date||"")===m;});};
  var bills=S.bills.map(function(b){var paid=paidOf(b);return {n:b.name||"Bill",amt:+b.amount||0,due:billDue(b,now),paid:paid};})
    .sort(function(a,b){return a.due.localeCompare(b.due);});
  var billsTotal=bills.reduce(function(x,b){return x+b.amt;},0),billsLeft=bills.reduce(function(x,b){return x+(b.paid?0:b.amt);},0);
  var returns=S.entries.filter(function(e){return e.returnBy&&daysLeft(e.returnBy)>=0&&daysLeft(e.returnBy)<=14&&!fullyReturned(e);})
    .sort(function(a,b){return a.returnBy.localeCompare(b.returnBy);}).slice(0,5).map(function(e){return {w:title(e),by:e.returnBy};});
  var mine=S.entries.filter(function(e){return e.date===t;});
  var streak=0,c=new Date();if(!covered(iso(c)))c.setDate(c.getDate()-1);
  while(streak<400&&covered(iso(c))){streak++;c.setDate(c.getDate()-1);}
  return {d:t,cur:"CAD",month:m,spent:Math.round(sum(inMonth)*100)/100,lastMonthSoFar:Math.round(sum(lastSoFar)*100)/100,top:top,
    todayDone:covered(t),todaySpent:Math.round(sum(mine)*100)/100,billsTotal:billsTotal,billsLeft:billsLeft,bills:bills.slice(0,8),
    returns:returns,inbox:S.entries.filter(function(e){return e.needsDetails;}).length,streak:streak};
}
function dashKick(ms){
  if(!window.PixoraSummary)return;
  PixoraSummary.schedule("spendlog",function(){
    if(!fdb||!cuser||!DEK||!S.ready)return null;
    return {fdb:fdb,uid:cuser.uid,build:dashSummary};
  },ms);
}
function cloudStop(){
  cloudLive=false;if(cloudUnsub){try{cloudUnsub();}catch(e){}cloudUnsub=null;}
  if(pushTimer){clearTimeout(pushTimer);pushTimer=null;}
  setCloud(cuser?"connecting":"off");
}
async function cloudListen(uid){
  var mark=(await kvGet("pulled:"+uid))||0;
  if(!cloudLive)return;
  var q=itemsCol().where("sv",">",firebase.firestore.Timestamp.fromMillis(mark));
  cloudUnsub=q.onSnapshot({includeMetadataChanges:true},async function(snap){
    if(!cloudLive||!DEK)return;
    var changed=false,top=mark,changes=snap.docChanges();
    for(var i=0;i<changes.length;i++){
      var c=changes[i];if(c.type==="removed")continue;
      var d=c.doc.data({serverTimestamps:"none"});if(!d.sv)continue;
      top=Math.max(top,d.sv.toMillis());
      try{if(await applyRemote(c.doc.id,d))changed=true;}catch(e){}
    }
    if(changed){await persist();if(S.ready)render();}
    if(!snap.metadata.fromCache){if(top>mark){mark=top;kvSet("pulled:"+uid,mark).catch(function(){});}if(!pushing)setCloud("synced");}
  },function(err){setCloud("error",err&&err.code);});
}
async function applyRemote(key,d){
  S.tomb=S.tomb||{};S.seen=S.seen||{};
  var isE=key.indexOf("e_")===0,isB=key.indexOf("b_")===0,id=key.slice(2),list=isE?S.entries:isB?S.bills:null;
  var idx=list?list.findIndex(function(x){return x.id===id;}):-1,cur=list?(idx>=0?list[idx].ts||0:0):(S.daysTs||0);
  if((d.ts||0)<=Math.max(cur,S.tomb[key]||0))return false;
  S.seen[key]=d.ts;delete S.tomb[key];
  if(d.del){
    if(list&&idx>=0){var gone=list[idx];list.splice(idx,1);[gone.receiptId,gone.receiptId2].forEach(function(r){if(r)recDel(r).catch(function(){});});}
    else if(key==="days"){S.days={};S.daysTs=d.ts;}
    return true;
  }
  var rec=JSON.parse(new TextDecoder().decode(await unseal(DEK,{iv:fromBytes(d.iv),ct:fromBytes(d.ct)})));
  if(key==="days"){S.days=rec||{};S.daysTs=d.ts;return true;}
  rec.id=id;rec.ts=d.ts;
  if(idx>=0)list[idx]=rec;else list.push(rec);
  if(isE)sortEntries(S.entries);
  return true;
}
function cloudKick(ms){
  if(!cloudLive)return;
  if(pushTimer)clearTimeout(pushTimer);
  pushTimer=setTimeout(function(){pushTimer=null;cloudPush();},ms==null?800:ms);
}
async function cloudPush(){
  if(!cloudLive||!DEK||!cuser)return;
  if(pushing){pushAgain=true;return;}
  pushing=true;setCloud(navigator.onLine===false?"offline":"syncing");
  var uid=cuser.uid;
  try{
    var mark=(await kvGet("pushed:"+uid))||0,ops=[],seen=S.seen||{},top=mark;
    S.entries.forEach(function(e){if((e.ts||0)>mark&&seen["e_"+e.id]!==e.ts)ops.push(["e_"+e.id,e,e.ts]);});
    S.bills.forEach(function(b){if((b.ts||0)>mark&&seen["b_"+b.id]!==b.ts)ops.push(["b_"+b.id,b,b.ts]);});
    if((S.daysTs||0)>mark&&seen.days!==S.daysTs)ops.push(["days",S.days,S.daysTs]);
    Object.keys(S.tomb||{}).forEach(function(k){if(S.tomb[k]>mark)ops.push([k,null,S.tomb[k]]);});
    [S.entries,S.bills].forEach(function(l){l.forEach(function(r){if((r.ts||0)>top)top=r.ts;});});
    top=Math.max(top,S.daysTs||0);Object.keys(S.tomb||{}).forEach(function(k){top=Math.max(top,S.tomb[k]);});
    for(var i=0;i<ops.length;i+=200){
      var batch=fdb.batch();
      for(var j=i;j<Math.min(i+200,ops.length);j++){
        var o=ops[j],ref=itemsCol().doc(o[0]);
        if(o[1]==null)batch.set(ref,{ts:o[2],del:true,sv:sts()});
        else{
          var body=Object.assign({},o[1]);delete body.ts;
          var box=await seal(DEK,new TextEncoder().encode(JSON.stringify(body)));
          batch.set(ref,{ts:o[2],iv:toBytes(box.iv),ct:toBytes(box.ct),sv:sts()});
        }
      }
      await batch.commit();
    }
    if(cuser&&cuser.uid===uid)await kvSet("pushed:"+uid,top);
    if(cuser&&cuser.uid===uid)setCloud("synced");
  }catch(e){setCloud(navigator.onLine===false?"offline":"error",e&&e.code);}
  finally{pushing=false;if(pushAgain){pushAgain=false;cloudKick(300);}}
}
/* Receipt photos stay on the phone that took them and are never uploaded. An earlier version uploaded
   them for a short time; any it left in the account are removed here. */
async function photoCleanup(ph){
  var refs=[];
  ph.forEach(function(p){var a=String(p).split(":"),n=+a[1]||1;for(var k=0;k<n;k++)refs.push(photosCol().doc(a[0]+"_"+k));});
  for(var i=0;i<refs.length;i+=400){var b=fdb.batch();refs.slice(i,i+400).forEach(function(r){b.delete(r);});await b.commit();}
  await userDoc().update({ph:[]});
}
async function cloudMetaPush(){
  if(!fdb||!cuser)return;
  var meta=await kvGet("meta");
  if(cloudLive&&meta.kind!=="pixora")await userDoc().set(metaToCloud(meta),{merge:true});
}
/* Removes this person's Spend Log data from their Pixora account. */
async function cloudWipe(){
  if(!fdb||!cuser)return;
  var s=await userDoc().get(),ph=s.exists&&Array.isArray(s.data().ph)?s.data().ph:[],refs=[];
  ph.forEach(function(p){var a=String(p).split(":"),n=+a[1]||1;for(var k=0;k<n;k++)refs.push(photosCol().doc(a[0]+"_"+k));});
  var items=await itemsCol().get();items.forEach(function(d){refs.push(d.ref);});
  refs.push(userDoc());
  for(var i=0;i<refs.length;i+=400){var b=fdb.batch();refs.slice(i,i+400).forEach(function(r){b.delete(r);});await b.commit();}
  var uid=cuser.uid;["pushed:","pulled:","photosUp:"].forEach(function(p){kvSet(p+uid,null).catch(function(){});});
}
/* Joining an account that already holds Spend Log data from another phone: unwrap that data key with
   the passcode set there, re-encrypt this phone's data with it, and from then on both phones share one key. */
async function cloudJoin(pass){
  var cm=cloudConflict.meta,raw=await unseal(await kek(pass,cm.salt,cm.iter),cm.wrapped);
  var nk=await importDek(raw);raw.fill(0);
  var ids=await recKeys();
  for(var i=0;i<ids.length;i++){var r=await recGet(ids[i]);if(!r)continue;var b=await seal(nk,await unseal(DEK,r));await recSet(ids[i],{iv:b.iv,ct:b.ct,type:r.type});}
  DEK=nk;await kvSet("meta",cm);
  S.entries.forEach(function(e){e.ts=Math.max(e.ts||0,1);});S.bills.forEach(function(b){b.ts=Math.max(b.ts||0,1);});
  if(Object.keys(S.days||{}).length)S.daysTs=Math.max(S.daysTs||0,1);
  S.seen={};await persist();await kvSet("pushed:"+cuser.uid,0);await kvSet("photosUp:"+cuser.uid,{});
  await rememberKey();cloudConflict=null;await cloudStart();
}
async function cloudReplace(){
  await cloudWipe();
  S.entries.forEach(function(e){e.ts=Math.max(e.ts||0,1);});S.bills.forEach(function(b){b.ts=Math.max(b.ts||0,1);});
  S.seen={};await persist();cloudConflict=null;await cloudStart();
}
var AUTH_MSG={"auth/invalid-credential":"That email and password don't match a Pixora account.","auth/wrong-password":"That email and password don't match a Pixora account.","auth/user-not-found":"That email and password don't match a Pixora account.","auth/invalid-login-credentials":"That email and password don't match a Pixora account.","auth/email-already-in-use":"There is already a Pixora account with that email. Tap Sign in instead.","auth/weak-password":"Use at least 6 characters for the password.","auth/invalid-email":"That doesn't look like an email address.","auth/network-request-failed":"No connection. Connect to the internet and try again.","auth/too-many-requests":"Too many tries. Wait a few minutes and try again."};
async function acctAuth(mode,email,pw){
  await cloudInit();
  if(!fdb)throw {code:"cloud/unavailable",message:"The Pixora account service couldn't start here."};
  email=(email||"").trim();
  if(!/^\S+@\S+\.\S+$/.test(email))throw {code:"auth/invalid-email"};
  if(mode==="reset"){await firebase.auth().sendPasswordResetEmail(email);return null;}
  if(!pw)throw {code:"auth/missing-password",message:"Type your password."};
  var c=mode==="create"?await firebase.auth().createUserWithEmailAndPassword(email,pw):await firebase.auth().signInWithEmailAndPassword(email,pw);
  T(mode==="create"?"account_create":"signin");
  cuser=c.user;return cuser;
}
function authText(e){return AUTH_MSG[e&&e.code]||(e&&e.message)||"Something went wrong. Try again.";}
function acctForm(prefix,onDone){
  var msg=h("p",{class:"err",role:"alert",hidden:true});
  var em=h("input",{type:"email",id:prefix+"-email",autocomplete:"username",autocapitalize:"off",spellcheck:"false",inputmode:"email"});
  var pw=h("input",{type:"password",id:prefix+"-pw",autocomplete:"current-password"});
  function go(mode){return async function(){
    msg.hidden=true;msg.style.color="";
    var btns=wrap.querySelectorAll("button");btns.forEach(function(b){b.disabled=true;});
    try{
      await acctAuth(mode,em.value,pw.value);
      if(mode==="reset"){msg.style.color="var(--muted)";msg.textContent="If a Pixora account uses that email, a reset link is on its way. Check your spam folder too.";msg.hidden=false;}
      else{pw.value="";await onDone();}
    }catch(e){msg.textContent=authText(e);msg.hidden=false;}
    btns.forEach(function(b){b.disabled=false;});
  };}
  var wrap=h("div",{class:"field",style:"gap:12px"},
    h("div",{class:"field"},h("label",{for:prefix+"-email",text:"Email"}),em),
    h("div",{class:"field"},h("label",{for:prefix+"-pw",text:"Password"}),pw),msg,
    h("div",{class:"btnrow"},
      h("button",{type:"button",class:"btn primary",text:"Sign in",onclick:go("signin")}),
      h("button",{type:"button",class:"btn",text:"Create account",onclick:go("create")}),
      h("button",{type:"button",class:"btn quiet",text:"Forgot password",onclick:go("reset")})));
  return wrap;
}
/* First screen on a phone with no Spend Log data yet. */
function showAccount(problem){
  $("app").hidden=true;$("lock").hidden=true;$("acct").hidden=false;
  var box=$("acctBody");box.textContent="";
  box.append(acctForm("a",async function(){$("acct").hidden=true;await routeSignedIn();}));
  box.append(h("button",{type:"button",class:"btn quiet",style:"align-self:flex-start",text:"Use on this phone only, without an account",onclick:function(){$("acct").hidden=true;showLock("setup");}}));
  if(problem){box.prepend(h("p",{class:"err",role:"alert",text:problem}));}
}
async function routeSignedIn(){
  var raw=null,mk=null;
  try{var snap=await userDoc().get();raw=snap.exists&&snap.data().vid?snap.data():null;mk=await getMk();}
  catch(e){showAccount("Couldn't reach your Pixora account. Check the connection and sign in again.");return;}
  if(raw&&!raw.pk){var cm=metaFromCloud(raw);delete cm.ph;await kvSet("meta",cm);vaultKind="legacy";showLock("unlock",null,"cloud");return;}
  pxCtx={mk:mk,raw:raw,fromCloud:true};
  showLock(mk?"pxunlock":"pxset",null,"cloud");
}
function cloudPanel(){
  var p=h("div",{class:"panel"},h("h3",{text:"Pixora account"}));
  if(!fdb&&!window.firebase){p.append(h("p",{class:"small muted",text:"The account service isn't available in this view."}));return p;}
  if(!cuser){
    p.append(h("p",{class:"small muted",text:"Sign in with your Pixora account to back up Spend Log and use it on more than one phone. Your purchases, items, bills and returns are encrypted on this phone before they're uploaded, so nobody else can read them, including whoever runs Pixora. Receipt photos stay on this phone only."}));
    p.append(acctForm("s",async function(){render();await cloudStart();render();}));
    return p;
  }
  p.append(h("p",{class:"small",text:"Signed in as "+(cuser.email||"your Pixora account")+"."}));
  if((cloudConflict&&cloudConflict.kind==="pixora")||pxNeed)p.append(h("p",{class:"small",style:"font-weight:600",text:"Finish the step at the top of the screen to keep Spend Log in sync."}));
  if(cloudState==="conflict"&&cloudConflict&&cloudConflict.kind==="pixora"){}
  else if(cloudState==="conflict"){
    var msg=h("p",{class:"err",role:"alert",hidden:true});
    p.append(h("p",{class:"small",style:"font-weight:600",text:"This account already has Spend Log data from another phone, protected by a different passcode. Enter that passcode to combine it with what's on this phone."}),
      pwField("s-joinpw","Passcode from your other phone","current-password"),msg);
    var jb=h("button",{type:"button",class:"btn primary",text:"Combine",onclick:async function(){
      jb.disabled=true;jb.textContent="Combining…";
      try{await cloudJoin($("s-joinpw").value);toast("Combined. Both phones now use the same passcode.");render();}
      catch(e){msg.textContent="That passcode doesn't open the data in your account.";msg.hidden=false;jb.disabled=false;jb.textContent="Combine";}
    }});
    var rb=h("button",{type:"button",class:"btn danger",text:joinWipeArmed?"Tap again: deletes the account's Spend Log data":"I forgot it: replace the account's data with this phone's",onclick:async function(){
      if(!joinWipeArmed){joinWipeArmed=true;render();return;}
      joinWipeArmed=false;rb.disabled=true;
      try{await cloudReplace();toast("Your account now holds this phone's data.");}catch(e){toast("Couldn't reach your account. Try again.");}
      render();
    }});
    p.append(h("div",{class:"btnrow"},jb,rb));
  }else{
    var when=lastSync?new Date(lastSync).toLocaleTimeString("en-CA",{hour:"numeric",minute:"2-digit"}):"";
    p.append(h("p",{class:"small muted",text:cloudState==="synced"?"Your data is backed up"+(when?" (last checked "+when+")":"")+". Changes from your other phones show up here on their own. Receipt photos stay on the phone that took them; a full backup file carries them to a new phone.":cloudState==="offline"?"Offline. Changes are kept on this phone and upload when you're back online.":cloudState==="error"?"Sync paused"+(cloudErr?" ("+cloudErr+")":"")+". Tap Sync now to try again.":"Syncing…"}));
    p.append(h("div",{class:"btnrow"},
      h("button",{type:"button",class:"btn",text:"Sync now",onclick:function(){cloudStart().then(render);}}),
      h("button",{type:"button",class:"btn quiet",text:"Sign out",onclick:async function(){cloudStop();await firebase.auth().signOut();cuser=null;render();toast("Signed out. Your data stays on this phone.");}})));
  }
  return p;
}
var joinWipeArmed=false;
addEventListener("offline",function(){if(cuser&&cloudLive)setCloud("offline");});
addEventListener("online",function(){if(cuser&&DEK&&(cloudState==="offline"||cloudState==="error"))cloudStart();});


/* ---------- One Pixora passcode ----------
   Same scheme as pixora-kit.js in the other Pixora apps: a master secret kept in apps/pixora/users/<uid>,
   stored only wrapped by the Pixora passcode. Spend Log derives its own app key from it (HKDF info
   "pixora-app:spendlog"), so no other Pixora app can read Spend Log data. That app key wraps the Spend Log
   data key ("pk" in the Spend Log account doc). One passcode unlocks every Pixora app, typed once per phone.
   People who use Spend Log without an account keep a Spend Log passcode on that phone instead. */
var PX_ITER=600000,vaultKind="legacy",pxCtx=null,pxNeed=null,pxArm=false;
function b64(u){var s="",i;u=u8(u);for(i=0;i<u.length;i+=0x8000)s+=String.fromCharCode.apply(null,u.subarray(i,i+0x8000));return btoa(s);}
function unb64(s){var b=atob(s),o=new Uint8Array(b.length),i;for(i=0;i<b.length;i++)o[i]=b.charCodeAt(i);return o;}
function masterDoc(){return fdb.doc("apps/pixora/users/"+cuser.uid);}
async function getMk(){var s=await masterDoc().get();return s.exists&&s.data().mk&&s.data().mk.id?s.data().mk:null;}
async function pxAppKey(m){
  var base=await crypto.subtle.importKey("raw",m,"HKDF",false,["deriveKey"]),te=new TextEncoder();
  return crypto.subtle.deriveKey({name:"HKDF",hash:"SHA-256",salt:te.encode("pixora"),info:te.encode("pixora-app:spendlog")},base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
async function pxMaster(pass,mk){
  var k=await kek(pass,unb64(mk.salt),Math.min(Math.max(+mk.iter||PX_ITER,100000),2000000));
  var o=JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(mk.iv)},k,unb64(mk.ct))));
  return unb64(o.m);
}
async function pxWrapMaster(pass,m,id){
  var salt=rnd(16),iv=rnd(12),k=await kek(pass,salt,PX_ITER);
  var ct=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:iv},k,new TextEncoder().encode(JSON.stringify({m:b64(m)}))));
  return {v:1,id:id,salt:b64(salt),iter:PX_ITER,iv:b64(iv),ct:b64(ct)};
}
/* A new Pixora passcode for all Pixora apps. Apps that can't open their cloud copy with it ask once and re-lock. */
async function pxNewMaster(pass){
  var m=rnd(32),id=b64(rnd(9)).replace(/[+/=]/g,""),mk=await pxWrapMaster(pass,m,id);
  await masterDoc().set({mk:mk},{merge:true});
  var ak=await pxAppKey(m);m.fill(0);await kvSet("mk",mk);T("px_passcode_set");
  return {mk:mk,ak:ak};
}
async function pxEnter(pass,mk){var m=await pxMaster(pass,mk),ak=await pxAppKey(m);m.fill(0);await kvSet("mk",mk);return ak;}
async function pkNew(ak,mid){
  var raw=rnd(32),iv=rnd(12),ct=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:iv},ak,raw));
  var key=await importDek(raw);raw.fill(0);return {key:key,pk:{mid:mid,iv:iv,ct:ct}};
}
async function pkOpen(ak,pk){
  var raw=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:u8(pk.iv)},ak,u8(pk.ct)));
  var key=await importDek(raw);raw.fill(0);return key;
}
function pkToCloud(pk){return {mid:pk.mid,iv:toBytes(pk.iv),ct:toBytes(pk.ct)};}
function pkFromCloud(p){return p&&p.mid?{mid:p.mid,iv:fromBytes(p.iv),ct:fromBytes(p.ct)}:null;}
function blankState(){S.entries=[];S.bills=[];S.days={};S.daysTs=0;S.tomb={};S.seen={};}
async function resealReceipts(nk){
  var ids=await recKeys();
  for(var i=0;i<ids.length;i++){var r=await recGet(ids[i]);if(!r)continue;try{var b=await seal(nk,await unseal(DEK,r));await recSet(ids[i],{iv:b.iv,ct:b.ct,type:r.type});}catch(e){}}
}
/* A brand-new Spend Log under the Pixora passcode. */
async function pxCreateVault(ak,mid){
  var r=await pkNew(ak,mid);
  DEK=r.key;blankState();vaultKind="pixora";
  await kvSet("meta",{v:2,kind:"pixora",vid:rid(),mts:Date.now()});await kvSet("pk",r.pk);
  await persist();
}
/* This phone opens the Spend Log already in the account. */
async function pxJoinCloud(ak,raw){
  DEK=await pkOpen(ak,pkFromCloud(raw.pk));blankState();vaultKind="pixora";
  await kvSet("meta",{v:2,kind:"pixora",vid:raw.vid,mts:raw.mts||0});await kvSet("pk",pkFromCloud(raw.pk));
  if(cuser){await kvSet("pulled:"+cuser.uid,0);await kvSet("pushed:"+cuser.uid,0);}
  await persist();
}
/* Re-lock this phone's Spend Log with the Pixora passcode: a fresh data key, everything re-encrypted with it,
   and the account copy replaced. Used to move off the old Spend Log passcode, or after a Pixora passcode reset. */
async function pxRekey(ak,mid){
  var old=await kvGet("meta"),r=await pkNew(ak,mid),vid=rid();
  await resealReceipts(r.key);
  DEK=r.key;vaultKind="pixora";
  await kvSet("meta",{v:2,kind:"pixora",vid:vid,mts:Date.now()});await kvSet("pk",r.pk);
  S.entries.forEach(function(e){e.ts=Math.max(e.ts||0,1);});S.bills.forEach(function(b){b.ts=Math.max(b.ts||0,1);});
  if(Object.keys(S.days||{}).length)S.daysTs=Math.max(S.daysTs||0,1);
  S.seen={};
  await persist();await rememberKey();
  if(cuser){
    cloudStop();
    await userDoc().set({v:2,vid:vid,from:(old&&old.vid)||"",pk:pkToCloud(r.pk),mts:Date.now(),at:sts(),ph:[]});
    await kvSet("pushed:"+cuser.uid,0);
  }
  pxNeed=null;cloudConflict=null;T("px_relock");
  if(cuser)await cloudStart();
}
/* This phone has its own Spend Log, and the account holds one from another phone: open the account's key,
   re-encrypt this phone's data with it and merge. Nothing on either side is lost. */
async function pxAdopt(ak,raw){
  var old=await kvGet("meta"),pk=pkFromCloud(raw.pk),nk=await pkOpen(ak,pk);
  await resealReceipts(nk);
  DEK=nk;vaultKind="pixora";
  await kvSet("meta",{v:2,kind:"pixora",vid:raw.vid,mts:raw.mts||0});await kvSet("pk",pk);
  S.entries.forEach(function(e){e.ts=Math.max(e.ts||0,1);});S.bills.forEach(function(b){b.ts=Math.max(b.ts||0,1);});
  if(Object.keys(S.days||{}).length)S.daysTs=Math.max(S.daysTs||0,1);
  await persist();await rememberKey();
  var uid=cuser.uid;await kvSet("pulled:"+uid,0);
  if(!(old&&raw.from&&raw.from===old.vid)){await kvSet("pushed:"+uid,0);S.seen={};await persist();}
  pxNeed=null;cloudConflict=null;T("px_combine");
  await cloudStart();
}
/* Has the Pixora passcode been reset in another app since this phone locked Spend Log with it? */
async function pxCheck(uid){
  var mk=await getMk(),pk=await kvGet("pk");
  if(!cuser||cuser.uid!==uid)return;
  if(!mk||!pk||mk.id!==pk.mid){pxNeed={why:"reset",mk:mk,loaded:true};if(S.ready)render();}
  else kvSet("mk",mk).catch(function(){});
}
async function pxNeedLoad(){
  try{var mk=await getMk();if(pxNeed)pxNeed.mk=mk;pxNeed&&(pxNeed.loaded=true);}catch(e){}
  if(S.ready)render();
}
/* The in-app card that asks for the Pixora passcode once: moving off the old passcode, after a reset, or to combine. */
var pxCardEl=null,pxCardKey="";
function pxCard(){
  var conflict=cloudConflict&&cloudConflict.kind==="pixora",need=pxNeed;
  if(!conflict&&!need){pxCardEl=null;pxCardKey="";return null;}
  var key=conflict?"c:"+cloudConflict.raw.vid:need.why+":"+(need.loaded?(need.mk?"enter":"set"):"wait");
  if(pxCardEl&&pxCardKey===key)return pxCardEl;
  pxCardKey=key;pxCardEl=pxCardBuild(conflict,need);return pxCardEl;
}
function pxCardBuild(conflict,need){
  var hasMk=conflict?true:!!(need&&need.mk),setting=!conflict&&need&&need.loaded&&!need.mk;
  var title=conflict?"Combine with your account":need.why==="reset"?"Enter your new Pixora passcode":setting?"Set your Pixora passcode":"Switch to your Pixora passcode";
  var text=conflict?"This Pixora account already has Spend Log data from another phone. Enter your Pixora passcode to combine it with what's on this phone. Nothing is lost on either side."
    :need.why==="reset"?"Your Pixora passcode was reset in another Pixora app. Enter the new one so this phone keeps Spend Log in sync."
    :setting?"Spend Log now uses one Pixora passcode, shared with your other Pixora apps. Set it once here. Your old Spend Log passcode is retired."
    :"Spend Log now uses your Pixora passcode, the same one as your other Pixora apps. Enter it once and your old Spend Log passcode is retired.";
  var msg=h("p",{class:"err",role:"alert",hidden:true});
  var p1=h("input",{type:"password",id:"px-p1",autocomplete:setting?"new-password":"current-password"});
  var p2=setting?h("input",{type:"password",id:"px-p2",autocomplete:"new-password"}):null;
  var go=h("button",{type:"submit",class:"btn primary",text:setting?"Set passcode":"Continue"});
  var f=h("form",{class:"panel pxcard",novalidate:true},h("h3",{text:title}),h("p",{class:"small",text:text}),
    h("div",{class:"field"},h("label",{for:"px-p1",text:"Pixora passcode"}),p1),
    p2?h("div",{class:"field"},h("label",{for:"px-p2",text:"Repeat it"}),p2):null,msg,h("div",{class:"btnrow"},go));
  if(!conflict&&need&&!need.loaded){go.disabled=true;go.textContent="Checking your account…";}
  f.addEventListener("submit",async function(ev){
    ev.preventDefault();msg.hidden=true;
    var a=p1.value,b=p2?p2.value:"";
    if(setting&&a.length<4){msg.textContent="Use at least 4 characters. Six or more is much harder to guess.";msg.hidden=false;return;}
    if(setting&&a!==b){msg.textContent="The two passcodes don't match.";msg.hidden=false;return;}
    go.disabled=true;go.textContent="Working…";
    try{
      var mk=await getMk(),ak;
      if(!mk){var r=await pxNewMaster(a);mk=r.mk;ak=r.ak;}
      else{try{ak=await pxEnter(a,mk);}catch(e){throw {code:"wrong"};}}
      if(conflict){
        var cpk=pkFromCloud(cloudConflict.raw.pk);
        if(!cpk||cpk.mid!==mk.id)throw {code:"stale"};
        await pxAdopt(ak,cloudConflict.raw);toast("Combined. This phone and your account now match.");
      }else{await pxRekey(ak,mk.id);toast("Done. Spend Log now opens with your Pixora passcode.");}
      render();
    }catch(e){
      go.disabled=false;go.textContent=setting?"Set passcode":"Continue";
      msg.textContent=e&&e.code==="wrong"?"That isn't your Pixora passcode.":e&&e.code==="stale"?"The Spend Log data in your account was locked before your Pixora passcode was reset, so nothing can open it now. Use the button below to replace it with this phone's data.":navigator.onLine===false?"No connection. Connect to the internet and try again.":"Something went wrong. Try again.";
      msg.hidden=false;
      if(e&&e.code==="stale"&&!f.querySelector(".pxreplace"))f.append(h("div",{class:"btnrow pxreplace"},h("button",{type:"button",class:"btn danger",text:"Replace the account's Spend Log data with this phone's",onclick:async function(){
        try{await cloudWipe();S.seen={};await persist();cloudConflict=null;pxNeed={why:"reset",mk:await getMk(),loaded:true};pxCardEl=null;render();}catch(x){toast("Couldn't reach your account. Try again.");}
      }})));
    }
  });
  return f;
}
async function pxChangePass(cur,nw){
  var mk=await getMk();if(!mk)throw {code:"nomk"};
  var m;try{m=await pxMaster(cur,mk);}catch(e){throw {code:"wrong"};}
  var nmk=await pxWrapMaster(nw,m,mk.id);m.fill(0);
  await masterDoc().set({mk:nmk},{merge:true});await kvSet("mk",nmk);T("px_passcode_change");
}
function pxPassPanel(){
  var msg=h("p",{class:"err",role:"alert",hidden:true});
  var change=h("button",{type:"button",class:"btn",text:"Change Pixora passcode",onclick:async function(){
    var cur=$("s-cur").value,nw=$("s-new").value,cf=$("s-conf").value;
    var bad=nw.length<4?"Use at least 4 characters. Six or more is much harder to guess.":nw!==cf?"The two new passcodes don't match.":!cuser?"Sign in to your Pixora account first.":"";
    if(bad){msg.textContent=bad;msg.hidden=false;return;}
    change.disabled=true;change.textContent="Changing…";
    try{await pxChangePass(cur,nw);toast("Pixora passcode changed for all your Pixora apps.");render();}
    catch(e){msg.textContent=e&&e.code==="wrong"?"The current Pixora passcode is wrong.":"Couldn't reach your account. Check the connection and try again.";msg.hidden=false;change.disabled=false;change.textContent="Change Pixora passcode";}
  }});
  return h("div",{class:"panel"},h("h3",{text:"Pixora passcode"}),
    h("p",{class:"small muted",text:"One passcode for Spend Log and your other Pixora apps. Changing it here changes it everywhere. Phones that are already unlocked stay unlocked."}),
    pwField("s-cur","Current Pixora passcode","current-password"),pwField("s-new","New Pixora passcode","new-password"),pwField("s-conf","Repeat new passcode","new-password"),msg,h("div",{class:"btnrow"},change));
}
/* Lock screen when the Pixora passcode is the key. */
async function pxLockSubmit(pass,pass2){
  var ctx=pxCtx||{};
  if(lockMode==="pxset"){
    if(pass.length<4)throw {msg:"Use at least 4 characters."};
    if(pass!==pass2)throw {msg:"The two passcodes don't match."};
    if(ctx.startOver||(ctx.raw&&ctx.raw.pk)){try{await cloudWipe();}catch(e){throw {msg:"Couldn't reach your account. Check the connection and try again."};}try{await wipeAll();}catch(e){}}
    var r;try{r=await pxNewMaster(pass);}catch(e){throw {msg:"Couldn't reach your account. Check the connection and try again."};}
    await pxCreateVault(r.ak,r.mk.id);return;
  }
  var mk=ctx.mk||await kvGet("mk"),ak;
  if(!mk)throw {msg:"This phone needs the internet once to check your Pixora passcode."};
  try{ak=await pxEnter(pass,mk);}catch(e){throw {wrong:true};}
  if(ctx.fromCloud){
    if(ctx.raw&&ctx.raw.pk){
      var cpk=pkFromCloud(ctx.raw.pk);
      if(cpk.mid!==mk.id)throw {msg:"Spend Log in your account was locked before your Pixora passcode was reset. Open Spend Log on a phone where it's already open and it fixes itself, or tap Forgot it below to start Spend Log over.",stale:true};
      await pxJoinCloud(ak,ctx.raw);T("px_new_phone");
    }else{await pxCreateVault(ak,mk.id);T("px_first_vault");}
    return;
  }
  var pk=await kvGet("pk");
  DEK=null;await openWithKey(await pkOpen(ak,pk));
}

$("saveStatus").addEventListener("click",function(){if(S.ready){S.tab="settings";render();}});
(async function boot(){
  S.month=ym(today());
  if(!window.isSecureContext||!window.crypto||!crypto.subtle||!window.indexedDB){showLock("setup","This app needs to be opened from its https address to encrypt your data.");return;}
  try{
    var meta=await kvGet("meta"),saved=null;
    vaultKind=meta&&meta.kind==="pixora"?"pixora":"legacy";
    if(meta){
      try{keepOn=(await kvGet("keep"))!==false;if(keepOn)saved=await kvGet("dek");}catch(e){saved=null;}
      if(saved){try{await openWithKey(saved);enterApp();}catch(e){DEK=null;saved=null;kvSet("dek",null).catch(function(){});}}
    }
    if(!saved){
      if(meta){if(vaultKind==="pixora")cloudInit().catch(function(){});showLock(vaultKind==="pixora"?"pxunlock":"unlock");}
      else{var u0=await cloudInit();if(u0)await routeSignedIn();else showAccount();}
    }
  }
  catch(e){showLock("setup","Storage is blocked here. Turn off Private Browsing, then open the app again.");}
  if("serviceWorker" in navigator)navigator.serviceWorker.register("sw.js").catch(function(){});
})();
/* Count which kinds of saves happen: new purchase vs edit, bills, returns, no-spend days. */
(function(){
  if(window.PixoraUsage)PixoraUsage.init("spendlog","spendlog-v11",function(){return fdb&&cuser?fdb:null;});
  var wrap=function(name,pick){var f=store[name];store[name]=function(x){try{T(pick?pick.apply(null,arguments):"store_"+name);}catch(e){}return f.apply(store,arguments);};};
  wrap("saveEntry",function(e){
    if(e.needsDetails&&!e.id)return "bank_row_saved";
    if(e.billId)return "bill_marked_paid";
    if(e.ret||(e.items||[]).some(function(i){return i.ret;}))return "return_recorded";
    var k=e.id&&S.entries.some(function(x){return x.id===e.id;})?"entry_edit":"entry_new";
    return k+(Array.isArray(e.items)&&e.items.length?"_itemized":"");
  });
  wrap("deleteEntry");wrap("saveBill");wrap("deleteBill");
  wrap("setNoSpend",function(d,on){return on?"no_spend_day":"no_spend_undo";});
})();
