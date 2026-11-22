/* Spend Log: subscription watcher and warranty reminders.
   Subscriptions are found from what you've logged: the same place charging a similar amount on a steady
   rhythm (weekly, monthly, quarterly or yearly). Nothing is sent anywhere; it all runs on the phone.
   Kept in its own file; the main app calls SubWatch.detect / viewSubs / viewWarranty and the alert helpers. */
(function(root){
"use strict";
var CAD=[[7,"weekly",2],[14,"every 2 weeks",3],[30.4,"monthly",6],[91.3,"every 3 months",12],[365.25,"yearly",25]];
function dnum(s){var p=String(s).split("-");return Date.UTC(+p[0],+p[1]-1,+p[2])/86400000;}
function fromNum(n){var d=new Date(n*86400000);return d.getUTCFullYear()+"-"+String(d.getUTCMonth()+1).padStart(2,"0")+"-"+String(d.getUTCDate()).padStart(2,"0");}
/* "NETFLIX.COM 866-579" and "Netflix" become the same key. */
function mkey(e){
  var s=String(e.where||e.what||"").toLowerCase().replace(/\.(com|ca|net)\b/g," ").replace(/[*#].*$/,"").replace(/\d{3,}/g," ").replace(/[^a-z& ]/g," ").replace(/\b(inc|ltd|llc|corp|canada|ca|ont|on|toronto|www|payment|purchase|pos|recurring|subscription|monthly)\b/g," ").replace(/\s+/g," ").trim();
  return s.split(" ").slice(0,3).join(" ");
}
function median(a){var b=a.slice().sort(function(x,y){return x-y;}),m=b.length>>1;return b.length%2?b[m]:(b[m-1]+b[m])/2;}
/* Returns subscriptions, newest charge first in each: {key,name,cadence,days,amount,prev,change,last,next,count,yearly,entries} */
function detect(entries,todayIso){
  var groups={},out=[],t=dnum(todayIso);
  (entries||[]).forEach(function(e){
    if(e.needsDetails||!e.date||!(+e.amount>0))return;
    var k=mkey(e);if(!k||k.length<3)return;
    (groups[k]=groups[k]||[]).push(e);
  });
  Object.keys(groups).forEach(function(k){
    var g=groups[k].slice().sort(function(a,b){return a.date.localeCompare(b.date);});
    if(g.some(function(e){return e.subNo;}))return;
    var dates=[],seen={};g.forEach(function(e){if(!seen[e.date]){seen[e.date]=1;dates.push(dnum(e.date));}});
    if(dates.length<2)return;
    var gaps=[];for(var i=1;i<dates.length;i++)gaps.push(dates[i]-dates[i-1]);
    var med=median(gaps),c=null;
    CAD.forEach(function(x){if(Math.abs(med-x[0])<=x[2])c=x;});
    if(!c)return;
    var steady=gaps.filter(function(x){return Math.abs(x-c[0])<=c[2]*1.6;}).length/gaps.length;
    if(dates.length===2&&c[0]<28)return;               /* two weekly-looking charges are too thin to call */
    if(steady<0.6)return;
    var last=g[g.length-1],amt=+last.amount,amts=g.map(function(e){return +e.amount;}),typical=median(amts.slice(0,-1).length?amts.slice(0,-1):amts);
    if(Math.max.apply(null,amts)>Math.min.apply(null,amts)*2.2)return;  /* wildly different amounts: a store, not a subscription */
    var prevDiff=null;for(var j=g.length-2;j>=0;j--){if(Math.abs(+g[j].amount-amt)>0.009){prevDiff=+g[j].amount;break;}}
    var next=dnum(last.date)+Math.round(c[0]);
    if(t-dnum(last.date)>c[0]*2+c[2]*2)return;          /* stopped a while ago */
    out.push({key:k,name:last.where||last.what||k,cadence:c[1],days:c[0],amount:amt,prev:prevDiff,change:prevDiff!=null&&amt>prevDiff+0.009?amt-prevDiff:prevDiff!=null&&amt<prevDiff-0.009?amt-prevDiff:0,
      typical:typical,last:last.date,next:fromNum(next),count:g.length,monthly:amt*30.4/c[0],yearly:amt*365.25/c[0],entries:g});
  });
  return out.sort(function(a,b){return b.yearly-a.yearly;});
}
/* A warranty end date suggested from the purchase date. */
function addYears(iso,n){var p=iso.split("-");var d=new Date(+p[0]+n,+p[1]-1,+p[2]);return d.getFullYear()+"-"+String(d.getMonth()+1).padStart(2,"0")+"-"+String(d.getDate()).padStart(2,"0");}
var api={detect:detect,mkey:mkey,addYears:addYears};
if(typeof module!=="undefined"&&module.exports)module.exports=api;else root.SubWatch=api;
})(typeof self!=="undefined"?self:this);
