# Render each receipt as thermal paper, then "photograph" it: background, tilt, perspective, uneven light, blur, JPEG.
import json,random,math,io
from PIL import Image,ImageFilter,ImageDraw,ImageEnhance,ImageOps
from playwright.sync_api import sync_playwright
exec(open('receipts.py').read())
random.seed(7)
CSS="body{margin:0;background:#fff}.r{width:520px;padding:34px 26px 60px;background:#fbfaf6;font:20px/1.35 'DejaVu Sans Mono',monospace;color:#262626;letter-spacing:-.3px}.c{text-align:center}.l{white-space:pre}"
def html(rc):
    out=[]
    for l in rc["lines"]:
        if l.startswith("c:"):out.append('<div class="c">%s</div>'%l[2:])
        else:out.append('<div class="l">%s</div>'%(l if l else "&nbsp;"))
    return '<html><head><style>%s</style></head><body><div class="r">%s</div></body></html>'%(CSS,"".join(out))
def bg(w,h,kind):
    base={"jeans":(58,78,110),"seat":(32,32,36),"wood":(120,86,56),"table":(205,205,200)}[kind]
    im=Image.new("RGB",(w,h),base);px=im.load()
    n=Image.effect_noise((w//4,h//4),40).resize((w,h)).convert("L")
    return Image.composite(im,ImageEnhance.Brightness(im).enhance(1.35),n)
def photo(paper,kind,angle,scale,sideways=False,seed=0):
    random.seed(seed)
    W,H=3024,4032
    p=paper.convert("RGB")
    # crumple: subtle horizontal shading bands
    sh=Image.new("L",p.size,255);d=ImageDraw.Draw(sh)
    for _ in range(6):
        y=random.randint(0,p.height);d.rectangle([0,y,p.width,y+random.randint(8,40)],fill=random.randint(215,240))
    sh=sh.filter(ImageFilter.GaussianBlur(12));p=Image.composite(p,Image.new("RGB",p.size,(150,150,150)),sh)
    tw=int(W*scale);th=int(p.height*tw/p.width)
    p=p.resize((tw,th),Image.LANCZOS)
    # perspective: narrower at the top
    k=random.uniform(0.02,0.06)*tw
    p=p.transform(p.size,Image.QUAD,(-k,0,-0,th,tw,th,tw+k,0),Image.BICUBIC,fillcolor=None)
    mask=Image.new("L",p.size,0);ImageDraw.Draw(mask).polygon([(k,0),(0,th),(tw,th),(tw-k,0)],fill=255)
    p=p.rotate(angle,expand=True,resample=Image.BICUBIC);mask=mask.rotate(angle,expand=True)
    canvas=bg(W,H,kind)
    if p.height>H*0.95:
        s=H*0.95/p.height;p=p.resize((int(p.width*s),int(p.height*s)));mask=mask.resize(p.size)
    x=(W-p.width)//2+random.randint(-150,150);y=(H-p.height)//2+random.randint(-80,80)
    canvas.paste(p,(x,y),mask)
    # uneven light from one corner
    g=Image.linear_gradient("L").resize((W,H)).rotate(random.choice([30,120,210,300]))
    canvas=Image.composite(canvas,ImageEnhance.Brightness(canvas).enhance(0.72),g)
    canvas=canvas.filter(ImageFilter.GaussianBlur(random.uniform(0.6,1.4)))
    if sideways:canvas=canvas.rotate(90,expand=True)
    b=io.BytesIO();canvas.save(b,"JPEG",quality=82);return b.getvalue()
truth={}
with sync_playwright() as pw:
    br=pw.chromium.launch(executable_path='/usr/bin/google-chrome',args=['--no-sandbox']);pg=br.new_page(viewport={'width':600,'height':800},device_scale_factor=2)
    for i,rc in enumerate(R):
        pg.set_content(html(rc));el=pg.query_selector(".r");el.screenshot(path="html/%s.png"%rc["key"])
        paper=Image.open("html/%s.png"%rc["key"])
        kinds=["jeans","seat","wood","table"]
        variants=[("a",kinds[i%4],random.uniform(-6,6),random.uniform(0.32,0.45),False)]
        if i%2==0:variants.append(("b",kinds[(i+1)%4],random.uniform(-12,12),random.uniform(0.22,0.3),False))
        if rc["key"] in("nofrills","restaurant"):variants.append(("s",kinds[(i+2)%4],random.uniform(-4,4),0.4,True))
        for v,kind,ang,sc,side in variants:
            name="%s_%s.jpg"%(rc["key"],v);open("img/"+name,"wb").write(photo(paper,kind,ang,sc,side,seed=i*10+ord(v)))
            truth[name]=rc["truth"]
    br.close()
json.dump(truth,open("truth.json","w"),indent=1);print(len(truth),"images")
