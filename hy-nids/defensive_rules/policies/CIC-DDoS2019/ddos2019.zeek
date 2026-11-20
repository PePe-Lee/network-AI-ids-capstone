# Generic fixed-second behavior candidates; no dataset identifiers or labels.
# One row = one event. value is the measurement AT FIRST CROSSING, not event weight.
module DDoS2019;
export {
    redef enum Log::ID += { LOG };
    const udp_new_threshold: count = 100 &redef;
    const tcp_new_threshold: count = 50 &redef;
    const reflection_packet_threshold: count = 50 &redef;
    const udp_packet_threshold: count = 100 &redef;
    const udp_payload_byte_threshold: count = 100000 &redef;
    const reflection_source_ports: set[port] = {
        53/udp,123/udp,161/udp,1900/udp,389/udp,1434/udp,137/udp,111/udp,69/udp
    } &redef;
    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        signal: string &log;
        value: count &log;
        window: interval &log;
        evidence: string &log;
    };
}
redef udp_content_deliver_all_orig = T;
redef udp_content_deliver_all_resp = T;
type Bucket: record { second: double; value: count; fired: bool; };
# Expiry is only garbage collection; floor(timestamp) explicitly defines windows.
global buckets: table[string] of Bucket &write_expire=10sec;
global emitted: count = 0;
event zeek_init() { Log::create_stream(LOG, [$columns=Info, $path="ddos2019"]); }
function bump(c: connection, signal: string, scope: string, delta: count,
              threshold: count, evidence: string)
    {
    local key = fmt("%s|%s", signal, scope);
    local second = floor(time_to_double(network_time()));
    if ( key !in buckets || buckets[key]$second != second )
        buckets[key] = [$second=second, $value=0, $fired=F];
    buckets[key]$value += delta;
    if ( buckets[key]$fired || buckets[key]$value < threshold ) return;
    buckets[key]$fired = T;
    ++emitted;
    Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
        $signal=signal, $value=buckets[key]$value, $window=1sec,
        $evidence=fmt("%s; scope=%s; fixed_second=%.0f; first crossing only; candidate not confirmed attack", evidence, scope, second)]);
    }
function both(c: connection, kind: string, source: addr, target: addr,
              delta: count, threshold: count, evidence: string)
    {
    bump(c, fmt("2019/%s_TARGET",kind), fmt("target=%s",target), delta, threshold, evidence);
    bump(c, fmt("2019/%s_PAIR",kind), fmt("source=%s,target=%s",source,target), delta, threshold, evidence);
    }
event new_connection(c: connection)
    {
    local proto = get_port_transport_proto(c$id$resp_p);
    if ( proto == udp )
        both(c,"UDP_NEW",c$id$orig_h,c$id$resp_h,1,udp_new_threshold,"new UDP connections; not UDP packet count");
    if ( proto == tcp )
        both(c,"TCP_NEW",c$id$orig_h,c$id$resp_h,1,tcp_new_threshold,"new TCP connections; new_connection does not prove a SYN packet or SYN flood");
    }
event udp_contents(c: connection, is_orig: bool, contents: string)
    {
    local source = c$id$orig_h;
    local target = c$id$resp_h;
    local source_port = c$id$orig_p;
    if ( !is_orig ) { source=c$id$resp_h; target=c$id$orig_h; source_port=c$id$resp_p; }
    local direction = fmt("UDP observed direction source=%s target=%s source_port=%s; id retains Zeek connection orientation",source,target,source_port);
    both(c,"UDP_PACKETS",source,target,1,udp_packet_threshold,direction);
    both(c,"UDP_PAYLOAD_BYTES",source,target,|contents|,udp_payload_byte_threshold,direction);
    if ( source_port in reflection_source_ports )
        both(c,"UDP_REFLECTION_PORT_CANDIDATE",source,target,1,reflection_packet_threshold,
             fmt("%s; source service port candidate only; no amplification ratio or request/response proof",direction));
    }
event zeek_done() { print fmt("DDOS2019_AUDIT emitted=%d",emitted); }
