var W=require("../subs.js"),assert=require("assert"),n=0;function t(a,f){f();n++;console.log("ok  "+a);}
function e(d,where,amt,x){return Object.assign({id:d+where,date:d,where:where,amount:amt},x||{});}
var es=[e("2026-08-15","NETFLIX.COM 866-579",16.49),e("2026-09-15","Netflix",16.49),e("2026-10-15","NETFLIX.COM",18.99),e("2026-11-15","Netflix",18.99),
  e("2026-01-10","Amazon Prime",99),e("2025-01-10","Amazon Prime",99),
  e("2026-11-01","No Frills",84.2),e("2026-11-04","No Frills",31.5),e("2026-11-12","No Frills",120.9),e("2026-11-19","No Frills",15),
  e("2026-06-01","Old Gym",40),e("2026-07-01","Old Gym",40),e("2026-08-01","Old Gym",40),
  e("2026-10-03","Spotify",11.99),e("2026-11-03","Spotify",11.99,{subNo:1})];
t("finds monthly and yearly, flags the price rise",function(){
  var s=W.detect(es,"2026-11-21"),by={};s.forEach(function(x){by[x.key]=x;});
  assert.deepStrictEqual(Object.keys(by).sort(),["amazon prime","netflix"]);
  assert.strictEqual(by.netflix.cadence,"monthly");assert.strictEqual(by.netflix.next,"2026-12-15");assert.ok(Math.abs(by.netflix.change-2.5)<1e-9);
  assert.strictEqual(by["amazon prime"].cadence,"yearly");assert.strictEqual(by["amazon prime"].next,"2027-01-10");
});
t("ignores groceries, stopped ones and ones marked not a subscription",function(){
  var keys=W.detect(es,"2026-11-21").map(function(x){return x.key;});
  assert.ok(keys.indexOf("no frills")<0);assert.ok(keys.indexOf("old gym")<0);assert.ok(keys.indexOf("spotify")<0);
});
t("warranty helper",function(){assert.strictEqual(W.addYears("2026-02-28",1),"2027-02-28");});
console.log(n+" tests passed");
