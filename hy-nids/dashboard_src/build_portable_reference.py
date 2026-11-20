"""Build an offline, read-only version of the original results dashboard."""
from pathlib import Path
import argparse, json, re
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--out',type=Path,default=Path('대시보드_오프라인.html'))
output=parser.parse_args().out
dash=Path(__file__).resolve().parent
assert all((dash/n).exists() for n in ('common32.html','common32.js','common32.css'))
H=(dash/'common32.html').read_text(encoding='utf8')
H=H.replace('<link rel="stylesheet" href="/common32.css"><script defer src="/common32.js"></script>', '<style>'+ (dash/'common32.css').read_text(encoding='utf8') +'</style>')
H=re.sub(r'<header>.*?</header>', '<header><span class="brand">HY-NIDS <span>EXPERIMENT LAB</span></span><span>오프라인 제출본 · 저장된 평가 결과 조회</span></header>',H,flags=re.S)
data={ '/api/common32':json.loads((dash/'common32_data.json').read_text(encoding='utf-8-sig')),
       '/api/extended2017':{'data':json.loads((dash/'extended2017_data.json').read_text(encoding='utf-8-sig'))},
       '/api/extended2019':{'data':json.loads((dash/'extended2019_data.json').read_text(encoding='utf-8-sig'))}}
packed=json.dumps(data,ensure_ascii=False,separators=(',',':')).replace('<','\\u003c')
js=(dash/'common32.js').read_text(encoding='utf8').replace('fetch(', 'archivedFetch(')
assert '</script' not in js.lower() and 'http' not in '\n'.join(re.findall(r'\b(?:fetch|archivedFetch)\(.*?\)',js))
H=H.replace('</body>', '<script>const ARCHIVED='+packed+';async function archivedFetch(path){return {ok:Object.hasOwn(ARCHIVED,path),json:async()=>ARCHIVED[path]}}\n'+js+'</script></body>')
output.write_text(H,encoding='utf8')
