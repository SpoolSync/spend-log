/* Tally screens for subscriptions and warranties. Uses the main app's helpers (h, money, S, store...). */
(function(){
"use strict";
function subs(){return SubWatch.detect(S.entries,today());}
function dl(s){return dayLabel(s)+(s.slice(0,4)!==today().slice(0,4)?", "+s.slice(0,4):"");}
function cad(s){return s.cadence==="monthly"?"/month":s.cadence==="yearly"?"/year":s.cadence==="weekly"?"/week":" "+s.cadence;}
/* For alerts, More menu and Pixora Today. */
window.subAlerts=function(){
  var out=[];
  subs().forEach(function(s){
    var d=daysLeft(s.next);
    if(s.change>0&&daysLeft(s.last)>=-45)out.push({k:3,cls:"impulse",t:s.name+" went up "+money(s.change)+cad(s)+" (now "+money(s.amount)+")",go:"subs"});
    if(s.days>=80&&d>=0&&d<=10)out.push({k:d,cls:"want",t:s.name+" renews "+(d===0?"today":d===1?"tomorrow":"in "+d+" days")+" · "+money(s.amount),go:"subs"});
  });
  warranties().filter(function(e){var d=daysLeft(e.warrantyUntil);return d>=0&&d<=30;}).forEach(function(e){var d=daysLeft(e.warrantyUntil);
    out.push({k:d+10,cls:"want",t:"Warranty ends "+(d===0?"today":"in "+d+" days")+": "+title(e),go:"warranty"});});
  return out;
};
window.subSummary=function(){
  var s=subs(),m=0;s.forEach(function(x){m+=x.monthly;});
  return {count:s.length,monthly:Math.round(m*100)/100,
    ups:s.filter(function(x){return x.change>0&&daysLeft(x.last)>=-45;}).map(function(x){return {n:x.name,ch:Math.round(x.change*100)/100};}).slice(0,3),
    renew:s.filter(function(x){var d=daysLeft(x.next);return x.days>=80&&d>=0&&d<=10;}).map(function(x){return {n:x.name,on:x.next,amt:x.amount};}).slice(0,3),
    warranty:warranties().filter(function(e){var d=daysLeft(e.warrantyUntil);return d>=0&&d<=30;}).map(function(e){return {w:title(e),by:e.warrantyUntil};}).slice(0,3)};
};
function warranties(){return S.entries.filter(function(e){return e.warrantyUntil&&!(typeof fullyReturned==="function"&&fullyReturned(e));});}
window.subMoreRow=function(){
  var s=subs(),m=0,ups=0;s.forEach(function(x){m+=x.monthly;if(x.change>0&&daysLeft(x.last)>=-45)ups++;});
  return ["subs","Subscriptions",s.length?s.length+" found · about "+money(m)+" a month":"Found automatically from what you log",ups];
};
window.warrantyMoreRow=function(){
  var w=warranties().filter(function(e){return daysLeft(e.warrantyUntil)>=0;}),soon=w.filter(function(e){return daysLeft(e.warrantyUntil)<=30;}).length;
  return ["warranty","Warranties",w.length?w.length+" under warranty"+(soon?" · "+soon+" ending soon":""):"Add a warranty date to any purchase",soon];
};

window.viewSubs=function(v){
  var s=subs(),m=0,y=0;s.forEach(function(x){m+=x.monthly;y+=x.yearly;});

  if(!s.length){v.append(h("div",{class:"empty"},h("p",{text:"None found yet. Subscriptions show up here once the same place has charged you on a steady rhythm, at least twice for monthly or yearly ones. Bank imports fill this in fastest."})));return;}
  v.append(h("div",{class:"panel"},h("p",{class:"small muted",text:"Roughly, every month"}),h("p",{style:"font-size:30px;font-weight:700;margin:0",text:money(m)}),
    h("p",{class:"small muted",text:money(y)+" a year across "+s.length+(s.length===1?" subscription":" subscriptions")+". Worked out from your logged charges; amounts can drift."})));
  s.forEach(function(x){
    var d=daysLeft(x.next),row=h("div",{class:"panel",style:"gap:6px"},
      h("div",{style:"display:flex;justify-content:space-between;gap:10px;align-items:baseline"},h("b",{text:x.name}),h("span",{style:"font-weight:700",text:money(x.amount)+cad(x)})),
      h("p",{class:"small muted",text:x.cadence.charAt(0).toUpperCase()+x.cadence.slice(1)+" · "+x.count+" charges logged · last "+dl(x.last)+" · next about "+(d<0?dl(x.next)+" (overdue, maybe cancelled?)":d===0?"today":dl(x.next))}));
    if(x.change>0)row.append(h("p",{class:"small",style:"color:var(--impulse,#b83b26);font-weight:600",text:"Price went up "+money(x.change)+" (was "+money(x.prev)+"). That's "+money(x.change*365.25/x.days)+" more a year."}));
    else if(x.change<0)row.append(h("p",{class:"small",style:"font-weight:600",text:"Price went down "+money(-x.change)+"."}));
    if(x.days>=80)row.append(h("p",{class:"small muted",text:"Renews "+(x.cadence==="yearly"?"once a year":x.cadence)+". You'll get a reminder 10 days before."}));
    row.append(h("div",{class:"btnrow"},
      h("button",{type:"button",class:"btn quiet mini",text:"Not a subscription",onclick:async function(){
        for(var i=0;i<x.entries.length;i++){var e=Object.assign({},x.entries[i],{subNo:1});await store.saveEntry(e);}
        if(window.PixoraUsage)PixoraUsage.track("sub_not_subscription");toast(x.name+" won't be treated as a subscription.");render();
      }}),
      h("button",{type:"button",class:"btn quiet mini",text:"Add as a bill",onclick:async function(){
        if(S.bills.some(function(b){return SubWatch.mkey({where:b.name})===x.key;})){toast("There's already a bill for "+x.name+".");return;}
        await store.saveBill({id:Date.now().toString(36)+Math.random().toString(36).slice(2,7),name:x.name,amount:x.amount,dueDay:+x.next.slice(8,10),category:"bills"});
        if(window.PixoraUsage)PixoraUsage.track("sub_add_bill");toast(x.name+" added to your bills.");
      }})));
    v.append(row);
  });
  v.append(h("p",{class:"small muted",text:"Cancelled one? It drops off after it misses two cycles. Spot one that isn't here? Log its charges, or bring in your bank CSV."}));
  if(window.PixoraUsage)PixoraUsage.track("subs_view");
};
window.viewWarranty=function(v){
  var w=warranties().sort(function(a,b){return a.warrantyUntil.localeCompare(b.warrantyUntil);}),live=w.filter(function(e){return daysLeft(e.warrantyUntil)>=0;}),past=w.filter(function(e){return daysLeft(e.warrantyUntil)<0;});

  if(!w.length){v.append(h("div",{class:"empty"},h("p",{text:"Open any purchase and set \"Warranty until\". You'll get a reminder 30 days before it runs out, and the receipt photo stays with it for the claim."})));return;}
  function row(e){var d=daysLeft(e.warrantyUntil);return h("button",{type:"button",class:"mrow",onclick:function(){openEntry(e);}},
    h("span",{class:"mtx"},h("span",{class:"mt",text:title(e)}),h("span",{class:"ms",text:(d<0?"Ended ":d===0?"Ends today · ":"Until ")+dl(e.warrantyUntil)+(d>0?" · "+(d<=60?d+" days left":Math.round(d/30.4)+" months left"):"")+(e.where?" · "+e.where:"")})),
    h("span",{class:"chev","aria-hidden":"true",text:"›"}));}
  if(live.length){var l=h("div",{class:"mlist"});live.forEach(function(e){l.append(row(e));});v.append(l);}
  if(past.length){v.append(h("p",{class:"small muted",text:"Ended"}));var p=h("div",{class:"mlist"});past.slice(-10).reverse().forEach(function(e){p.append(row(e));});v.append(p);}
};

function wy(n){var d=$("f-date").value||today();$("f-warranty").value=n?SubWatch.addYears(d,n):"";}
document.addEventListener("click",function(e){var t=e.target;if(!t||!t.id)return;if(t.id==="f-w1")wy(1);else if(t.id==="f-w2")wy(2);else if(t.id==="f-w0")wy(0);});
})();
