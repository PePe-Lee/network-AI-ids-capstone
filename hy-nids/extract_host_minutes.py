"""Local packet semantics, completed TCP connections -> UTC host-minute features.
Not CICFlowMeter parity. Never reads a growing capture. Standard-library only.
"""
from __future__ import annotations
import argparse, collections, csv, gzip, hashlib, json, math, struct, heapq
from pathlib import Path
FIELDS=['Total Fwd Packets','Total Backward Packets','Total Length of Fwd Packets','Total Length of Bwd Packets','Flow Duration','Flow IAT Mean','SYN Flag Count','RST Flag Count','FIN Flag Count','PSH Flag Count','ACK Flag Count']
FEATURES=['flow_count','out_packets','in_packets','out_bytes','in_bytes','duration_mean_s','duration_max_s','flow_IAT_mean_s','SYN_sum','RST_sum','FIN_sum','PSH_sum','ACK_sum','TCP_fraction','UDP_fraction','peer_diversity','service_diversity','packets_per_60s','bytes_per_60s','self_loop_count','few_flow_flag']+['missing_fraction_'+x for x in FIELDS]
VERSION='packet-tcp-hostminute-v3.0-raw-generation-validated'

def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def dump(p,x):Path(p).write_text(json.dumps(x,indent=2,ensure_ascii=False,allow_nan=False)+'\n',encoding='utf8')
def write_jsonl(p,rows):
 with gzip.open(p,'wt',encoding='utf8') as f:
  for r in rows:f.write(json.dumps(r,allow_nan=False)+'\n')
def read_jsonl(p):
 with gzip.open(p,'rt',encoding='utf8') as f:return [json.loads(x) for x in f]
def minute(t):return int(t//60)*60

def packets(path, include_payload=False):
 with Path(path).open('rb') as f:
  h=f.read(24)
  if len(h)!=24:raise ValueError('Incomplete PCAP global header')
  magic=h[:4]; formats={b'\xd4\xc3\xb2\xa1':('<',1e6),b'\xa1\xb2\xc3\xd4':('>',1e6),b'\x4d\x3c\xb2\xa1':('<',1e9),b'\xa1\xb2\x3c\x4d':('>',1e9)}
  if magic not in formats:raise ValueError('Classic PCAP required')
  en,scale=formats[magic]
  if struct.unpack(en+'I',h[20:24])[0]!=1:raise ValueError('Ethernet link type required')
  idx=0
  while True:
   h=f.read(16)
   if not h:break
   if len(h)!=16:raise ValueError('Incomplete record header')
   sec,sub,cap,orig=struct.unpack(en+'IIII',h);b=f.read(cap);idx+=1
   if len(b)!=cap or cap<orig:raise ValueError('Truncated packet')
   ts=sec+sub/scale;off=14
   if len(b)<off:raise ValueError('Truncated Ethernet')
   typ=b[12:14]
   while typ in (b'\x81\x00',b'\x88\xa8'):
    typ=b[off+2:off+4];off+=4
   if typ!=b'\x08\x00':raise ValueError('Unexpected non-IPv4 captured packet')
   if len(b)<off+20:raise ValueError('Truncated IPv4')
   ihl=(b[off]&15)*4;total=struct.unpack('!H',b[off+2:off+4])[0];frag=struct.unpack('!H',b[off+6:off+8])[0]
   if frag&0x3fff:raise ValueError('IPv4 fragmentation requires reassembly; unsupported')
   if b[off+9]!=6:raise ValueError('Unexpected non-TCP packet')
   if total<ihl+20 or len(b)<off+total:raise ValueError('Invalid IPv4/TCP length')
   a='.'.join(map(str,b[off+12:off+16]));z='.'.join(map(str,b[off+16:off+20]));t=off+ihl
   ap,zp,seq,ack=struct.unpack('!HHII',b[t:t+12]);thl=(b[t+12]>>4)*4
   if thl<20 or total<ihl+thl:raise ValueError('Invalid TCP header length')
   record=dict(index=idx,ts=ts,src=a,dst=z,sp=ap,dp=zp,seq=seq,ack=ack,flags=b[t+13],payload_bytes=total-ihl-thl,wire_bytes=orig)
   if include_payload:record['tcp_payload']=b[t+thl:off+total]
   yield record

MOD = 2**32
MAX_SERIAL_SPAN = 2**31
LATENESS_S = 1.0
IDLE_S = 120.0


def endpoint(p):
 return p['src'], p['sp']


def bare_syn(p):
 return bool(p['flags'] & 2 and not p['flags'] & 16)


def closed(pp):
 return any(p['flags'] & 4 for p in pp) or len({endpoint(p) for p in pp if p['flags'] & 1}) == 2


def adopt_synack_prefix(pp, syn):
 """Only an exact SYN/ACK echo can identify a pre-SYN capture-order prefix.
 No data, FIN, RST, other client packets, nearest-time or interval-based join.
 """
 return bool(pp) and len({p['seq'] for p in pp}) == 1 and all(
  endpoint(p) == (syn['dst'], syn['dp']) and
  p['dst'] == syn['src'] and p['dp'] == syn['sp'] and
  p['flags'] == 18 and p['payload_bytes'] == 0 and
  p['ack'] == (syn['seq'] + 1) % MOD and
  abs(p['ts'] - syn['ts']) <= LATENESS_S for p in pp)


def validate_generation(pp, anchor):
 """Conservative captured-sequence coverage; not a full TCP implementation.
 Count retransmissions in features, but union their sequence intervals in proof.
 SYN and FIN each consume one serial number; arithmetic supports one wrap.
 Missing serial coverage, ambiguous half-space and nonmatching ACKs quarantine.
 """
 issues=set();initial={};intervals=collections.defaultdict(list);maxpos={}
 for p in pp:
  ep=endpoint(p)
  if p['flags'] & 2:
   if ep in initial and initial[ep] != p['seq']: issues.add('multiple_syn_sequences')
   initial.setdefault(ep,p['seq'])
   if p['payload_bytes']: issues.add('unsupported_syn_payload')
 if anchor is None:
  issues.add('missing_initial_syn')
 else:
  client=endpoint(anchor);server=(anchor['dst'],anchor['dp'])
  for p in pp:
   if p['flags'] & 2 and p['flags'] & 16:
    if endpoint(p) != server or p['ack'] != (anchor['seq']+1)%MOD:
     issues.add('synack_does_not_ack_initial_syn')
  # A SYN refused by exact RST/ACK is a completed reset connection, not a handshake.
  rejection=(len(initial)==1 and all(p is anchor or
   (endpoint(p)==client and bare_syn(p) and p['seq']==anchor['seq']) or
   (endpoint(p)==server and p['flags']==20 and p['payload_bytes']==0 and p['ack']==(anchor['seq']+1)%MOD)
   for p in pp) and any(p['flags']==20 for p in pp))
  if rejection:
   return dict(valid=not issues,issues=sorted(issues),mode='syn_reset_refusal',sequence_ranges={},coverage_complete=True)
 if len(initial)!=2: issues.add('missing_direction_syn_evidence')
 for p in pp:
  ep=endpoint(p)
  if ep not in initial: continue
  pos=(p['seq']-initial[ep])%MOD
  consume=p['payload_bytes']+bool(p['flags']&2)+bool(p['flags']&1)
  end=pos+consume
  if pos>=MAX_SERIAL_SPAN or end>=MAX_SERIAL_SPAN:
   issues.add('ambiguous_or_out_of_range_sequence');continue
  intervals[ep].append((pos,end));maxpos[ep]=max(maxpos.get(ep,0),pos)
 ranges={}
 for ep,isn in initial.items():
  reach=0
  for lo,hi in sorted(intervals[ep]):
   if lo>reach: issues.add('sequence_gap_or_wrong_generation')
   reach=max(reach,hi)
  ranges[f'{ep[0]}:{ep[1]}']=dict(initial=isn,span=reach)
  if maxpos.get(ep,0)>reach: issues.add('sequence_gap_or_wrong_generation')
 for p in pp:
  if not p['flags']&16:continue
  other=(p['dst'],p['dp']);key=f'{other[0]}:{other[1]}'
  if key not in ranges:continue
  ack=(p['ack']-ranges[key]['initial'])%MOD
  if ack>ranges[key]['span']:issues.add('ack_outside_captured_sequence')
 return dict(valid=not issues,issues=sorted(issues),mode='captured_sequence_coverage',sequence_ranges=ranges,coverage_complete=not issues)


def modular_intervals(start,span):
 if span>=MOD:return [(0,MOD-1)]
 end=start+span
 return [(start,end)] if end<MOD else [(start,MOD-1),(0,end%MOD)]


def sequence_disjoint(a,b):
 a=a.get('sequence_ranges',{});b=b.get('sequence_ranges',{})
 if len(a)!=2 or set(a)!=set(b):return False
 for ep in a:
  for lo,hi in modular_intervals(a[ep]['initial'],a[ep]['span']):
   for ll,hh in modular_intervals(b[ep]['initial'],b[ep]['span']):
    if max(lo,ll)<=min(hi,hh):return False
 return True


def extract_records(records,roles):
 """Assign raw record-order generations first; never globally timestamp-sort.
 A new ISN starts a new generation. Same-ISN SYN is a retransmission unless
 >120 seconds idle. Same-ISN SYN after closure is retained but quarantined.
 We deliberately do not guess ownership of late prior-generation packets:
 invalid sequence/ACK evidence quarantines their provisional generation.
 """
 active={};segments=[];total=collections.Counter();high=None;last_index=0
 def finish(k,why):
  g=active.pop(k);g['end_reason']=why;segments.append((k,g))
 for p in records:
  if p['index']<=last_index:raise ValueError('Raw packet indices must be strictly increasing')
  last_index=p['index']
  if high is not None and p['ts']<high:
   lag=high-p['ts'];total['timestamp_regression_records']+=1
   total['max_timestamp_regression_s']=max(lag,total['max_timestamp_regression_s'])
   if lag>LATENESS_S:raise ValueError('Timestamp regression exceeds frozen 1s bound; quarantine capture')
  high=max(high if high is not None else p['ts'],p['ts'])
  total['packets']+=1;total['payload_bytes']+=p['payload_bytes'];total['wire_bytes']+=p['wire_bytes']
  for bit in [2,4,1,8,16]:total['flag_'+str(bit)]+=bool(p['flags']&bit)
  if p['src'] not in roles or p['dst'] not in roles:raise ValueError('Unrecognized endpoint')
  if not ((roles[p['src']]=='server' and p['sp']==80 and roles[p['dst']] in ['normal_client','attack_client']) or
          (roles[p['dst']]=='server' and p['dp']==80 and roles[p['src']] in ['normal_client','attack_client'])):
   raise ValueError('Not lab client/server HTTP')
  k=tuple(sorted([(p['src'],p['sp']),(p['dst'],p['dp'])]));syn=bare_syn(p)
  if k in active:
   g=active[k];idle=p['ts']>g['high']+IDLE_S
   if idle:finish(k,'idle_120s')
   elif syn:
    if g['anchor'] is None and adopt_synack_prefix(g['pp'],p):
     g['anchor']=p;g['prefix_adopted']=True
    elif g['anchor'] is None or endpoint(g['anchor'])!=endpoint(p) or g['anchor']['seq']!=p['seq']:
     finish(k,'new_syn')
    elif closed(g['pp']):g['issues'].add('same_isn_syn_after_close')
  if k not in active:
   active[k]=dict(pp=[],anchor=p if syn else None,high=p['ts'],issues=set(),prefix_adopted=False)
  g=active[k];g['pp'].append(p);g['high']=max(g['high'],p['ts'])
 for k in list(active):finish(k,'capture_end')
 done=[];bytuple=collections.defaultdict(list)
 for k,g in segments:
  pp=g['pp'];tp=sorted(pp,key=lambda p:(p['ts'],p['index']));anchor=g['anchor'];origin=anchor or pp[0]
  r=dict(first=tp[0]['ts'],last=tp[-1]['ts'],src=origin['src'],dst=origin['dst'],sp=origin['sp'],dp=origin['dp'],
   first_packet=tp[0]['index'],last_packet=tp[-1]['index'],raw_first_packet=pp[0]['index'],raw_last_packet=pp[-1]['index'],
   generation_anchor_packet=origin['index'],initial_syn_ts=anchor['ts'] if anchor else None,
   initial_seq=anchor['seq'] if anchor else None,starts_with_syn=anchor is not None,
   packets=len(pp),fwd_packets=0,bwd_packets=0,fwd_bytes=0,bwd_bytes=0,flags=[0]*5,fin_directions=[],reset=False,
   client=origin['dst'] if roles[origin['src']]=='server' else origin['src'],end_reason=g['end_reason'],
   packet_indices=[p['index'] for p in pp],synack_prefix_adopted=g['prefix_adopted'],
   timestamps_reordered_within_generation=[p['index'] for p in pp]!=[p['index'] for p in tp])
  for p in pp:
   prefix='fwd' if endpoint(p)==endpoint(origin) else 'bwd'
   r[prefix+'_packets']+=1;r[prefix+'_bytes']+=p['payload_bytes']
   for i,bit in enumerate([2,4,1,8,16]):r['flags'][i]+=bool(p['flags']&bit)
   if p['flags']&1 and prefix not in r['fin_directions']:r['fin_directions'].append(prefix)
   if p['flags']&4:r['reset']=True
  r['duration_s']=r['last']-r['first'];r['iat_mean_s']=r['duration_s']/(r['packets']-1) if r['packets']>1 else 0.0
  r['tuple_group']='|'.join(f'{a}:{port}' for a,port in k)
  r['id']=hashlib.sha256((r['tuple_group']+'|'+str(r['generation_anchor_packet'])).encode()).hexdigest()
  r['generation_proof']=validate_generation(pp,anchor)
  r['generation_invalid']=sorted(g['issues']|set(r['generation_proof']['issues']))
  done.append(r);bytuple[r['tuple_group']].append(r)
 # Forward-only grouping for clean generations. Ownership uncertainty is a
 # separate capture/stage-level validity gate below, not a leakage-only issue.
 # No packet is guessed into an older generation; late-ACK contamination is
 # quarantined by sequence/ACK evidence in its provisional raw-order segment.
 for key,fs in bytuple.items():
  fs.sort(key=lambda r:r['raw_first_packet'])
  for i,r in enumerate(fs):
   own_valid=not r['generation_invalid']
   own_closed=r['reset'] or len(r['fin_directions'])==2
   disjoint=all(sequence_disjoint(old['generation_proof'],r['generation_proof']) for old in fs[:i])
   previous=fs[i-1] if i else None
   previous_valid=not previous['generation_invalid'] if previous else True
   previous_closed=(previous['reset'] or len(previous['fin_directions'])==2) if previous else True
   separate=own_valid and own_closed and previous_valid and previous_closed and disjoint
   if i and not disjoint:
    r['generation_invalid']=sorted(set(r['generation_invalid'])|{'unproved_reused_sequence_space'})
   r['leakage_group']=r['id'] if previous is None or separate else previous['leakage_group']
   r['reuse_proved_separate']=separate
   r['generation_id']=r['id']
   r['generation_proof']['packet_sequence_valid']=r['generation_proof']['valid']
   r['generation_proof']['valid']=not r['generation_invalid']
 # A provisional late old-generation packet can make the newer vector invalid
 # AND leave the old vector missing that packet. Do not certify either vector.
 # Quarantine the entire ambiguous reused tuple inside this extraction unit.
 # Callers MUST extract each finalized experimental stage and its drain alone;
 # cross-stage ambiguity is a data-validity failure, never a fit-membership edit.
 for key,fs in bytuple.items():
  if len(fs)>1 and any(r['generation_invalid'] for r in fs):
   shared=hashlib.sha256(('quarantined|'+key).encode()).hexdigest()
   for r in fs:
    r['generation_invalid']=sorted(set(r['generation_invalid'])|{'ambiguous_reused_tuple_packet_ownership'})
    r['generation_proof']['valid']=False;r['leakage_group']=shared;r['reuse_proved_separate']=False
 assert sum(r['packets'] for r in done)==total['packets']
 assert sum(r['fwd_bytes']+r['bwd_bytes'] for r in done)==total['payload_bytes']
 indices=[i for r in done for i in r['packet_indices']]
 assert len(indices)==len(set(indices))==total['packets']
 for i,bit in enumerate([2,4,1,8,16]):assert sum(r['flags'][i] for r in done)==total['flag_'+str(bit)]
 total['generations']=len(done);total['invalid_generations']=sum(bool(r['generation_invalid']) for r in done)
 return sorted(done,key=lambda r:(r['first'],r['id'])),dict(total)


def extract(path,roles):
 return extract_records(packets(path),roles)

def logs(root,phase):
 req=collections.defaultdict(list);events=[];opened={};hashes={}
 for p in sorted((root/'client_logs').glob(phase+'_*.jsonl')):
  hashes[p.name]=sha(p)
  for lineno,line in enumerate(p.open(encoding='utf8'),1):
   e=json.loads(line);e['source_file']=p.name;e['source_line']=lineno
   if e['event']=='request':e['start']=e['ts']-e['elapsed'];req[e['source_ip']].append(e)
   elif e['event']=='attack_event_start':opened[e['source_ip'],e['kind']]=e
   elif e['event']=='attack_event_end':
    a=opened.pop((e['source_ip'],e['kind']),None)
    if a:events.append(dict(source_ip=e['source_ip'],kind=e['kind'],start=a['ts'],end=e['ts'],request_limit=a['request_limit'],source_file=p.name,start_line=a['source_line'],end_line=lineno))
 if opened:raise ValueError('Unclosed attack events')
 return req,events,hashes

def label_flows(flows,roles,requests,events,phase):
 for r in flows:
  ip=r['client'];r['label']=None;r['labels']=[];r['label_basis']='unknown_source_or_evidence'
  # Roles come from controller topology, never classifier output. Only observed flows exist.
  if roles[ip]=='normal_client':r['label']=0;r['label_basis']='isolated_normal_workload_source'
  elif roles[ip]=='attack_client':
   ev=[e for e in events if e['source_ip']==ip and r['first']<=e['end'] and r['last']>=e['start']]
   rr=[e for e in requests[ip] if e['label']=='attack' and e['start']<=r['last']+.25 and e['ts']>=r['first']-.25]
   if ev and rr:r['label']=1;r['labels']=sorted({e['kind'] for e in ev});r['label_basis']='isolated_attack_source_event_and_request_overlap_not_exploit_success'
  if phase=='normal' and r['label']!=0:raise ValueError('Non-normal source in training capture')

def aggregate(flows,roles,phase,start,end):
 bins={}
 for r in flows:
  m=minute(r['first'])
  for ip in set([r['src'],r['dst']]):
   k=(ip,m);x=bins.setdefault(k,dict(key=[ip,m],phase=phase,role=roles[ip],flow_ids=[],tuple_groups=[],labels=[],label=0,first_flow=r['first'],last_flow=r['last'],sum=[0.0]*11,maxdur=0.0,peers=[],ports=[],self=0,invalid=[]))
   fw=ip==r['src'];v=[r['fwd_packets'],r['bwd_packets'],r['fwd_bytes'],r['bwd_bytes'],r['duration_s']*1e6,r['iat_mean_s']*1e6,*r['flags']]
   if not fw:v[0],v[1],v[2],v[3]=v[1],v[0],v[3],v[2]
   x['flow_ids'].append(r['id']);x['tuple_groups'].append(r['tuple_group']);x['last_flow']=max(x['last_flow'],r['last']);x['sum']=[a+b for a,b in zip(x['sum'],v)];x['maxdur']=max(x['maxdur'],r['duration_s']);x['peers'].append(r['dst'] if fw else r['src']);x['ports'].append(80);x['self']+=r['src']==r['dst'];x['labels']+=r['labels']
   if r['label']==1:x['label']=1
   elif r['label'] is None and x['label']!=1:x['label']=None
   x['invalid'].extend(r.get('generation_invalid',[]))
   if not r['starts_with_syn']:x['invalid'].append('missing_initial_syn')
   if not (r['reset'] or len(r['fin_directions'])==2):x['invalid'].append('incomplete_connection')
 for x in bins.values():
  n=len(x['flow_ids']);s=x.pop('sum');x['flow_count']=n;x['x']=[n,*s[:4],s[4]/n/1e6,x.pop('maxdur'),s[5]/n/1e6,*s[6:11],1.0,0.0,len(set(x.pop('peers'))),len(set(x.pop('ports'))),(s[0]+s[1])/60,(s[2]+s[3])/60,x.pop('self'),int(n<=1)]+[0.0]*11
  assert len(x['x'])==32 and all(math.isfinite(z) and z>=0 for z in x['x'])
  x['labels']=sorted(set(x['labels']));x['tuple_groups']=sorted(set(x['tuple_groups']));x['invalid']=sorted(set(x['invalid']));m=x['key'][1]
  if m<start or m+60>end:x['invalid'].append('partial_capture_minute')
  x['fingerprint']=hashlib.sha256(json.dumps([round(z,10) for z in x['x']],separators=(',',':')).encode()).hexdigest()
 return sorted(bins.values(),key=lambda x:(x['key'][1],x['key'][0]))

def split_normal(rows,first_epoch,last_epoch):
 base=minute(first_epoch);end=minute(last_epoch);b=[base+60,base+1800,base+1920,base+2280,base+2700,base+2820,end]
 def role(t):
  if b[0]<=t<b[1]:return 'train'
  if b[2]<=t<b[3]:return 'calibration_cdf'
  if b[3]<=t<b[4]:return 'calibration_threshold'
  if b[5]<=t<b[6]:return 'holdout'
  return 'embargo_or_partial'
 seen_groups={};seen={};collisions=set()
 for r in rows:
  r['split']=role(r['key'][1]);r['invalid']+=[] if role(r['last_flow'])==r['split'] else ['flow_crosses_split_boundary']
  if r['split']=='embargo_or_partial':r['invalid'].append('embargo_or_partial')
  if not r['invalid']:
   reused={g for g in r['tuple_groups'] if g in seen_groups and seen_groups[g]!=r['split']}
   if reused:r['invalid'].append('tuple_group_seen_in_earlier_split');collisions.update(reused)
   fp=r['fingerprint']
   if fp in seen and seen[fp]!=r['split']:r['invalid'].append('rounded_10dp_feature_duplicate_of_earlier_split')
   if not r['invalid']:
    seen[fp]=r['split']
    for g in r['tuple_groups']:seen_groups[g]=r['split']
  r['eligible']=not r['invalid'] and r['label'] is not None

 return dict(boundaries_epoch=b,base_epoch=base,policy='29 full train minutes; two-minute embargo; 6 CDF/early-stop minutes; 7 threshold minutes; two-minute embargo; full holdout minutes to capture end. Whole-bin exclusion for crossing/incomplete flows, later-only bidirectional tuple reuse and earlier-split rounded-10-decimal feature duplicate. Earlier partitions never depend on later membership. Same roles across all IPs.',later_reused_tuple_groups=len(collisions))

# Use prepare_generation.py for explicit, immutable input/output preparation.
