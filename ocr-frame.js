/* Runs inside ocr.html. Takes a photo from the app, returns the text it found with positions. */
var engine=null;
addEventListener("message",async function(ev){
  if(ev.origin!==location.origin||ev.source!==parent||!ev.data||ev.data.kind!=="read")return;
  var id=ev.data.id,url=null;
  try{
    if(!engine)engine=PPOCR.create(new URL(".",location.href).href);
    var ocr=await engine;url=URL.createObjectURL(ev.data.blob);
    var r=await ocr.detect(url);
    parent.postMessage({kind:"read-done",id:id,boxes:r.texts.map(function(t){return {t:t.text,x:t.box[0][0],y:t.box[0][1]};})},location.origin);
  }catch(e){
    engine=null;
    parent.postMessage({kind:"read-done",id:id,error:String((e&&e.message)||e)},location.origin);
  }finally{if(url)URL.revokeObjectURL(url);}
});
parent.postMessage({kind:"reader-ready"},location.origin);
