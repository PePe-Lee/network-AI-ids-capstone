# Supplemental plaintext HTTP syntax evidence. No addresses, labels, IDs or scenario names.
# Reuse the existing structured signal log so strict UID/flow attribution remains possible.
module InSampleOpt;
global lab_method: table[string] of string &write_expire=10min;
global lab_body: table[string] of string &write_expire=10min;
global lab_gap: set[string] &create_expire=10min;

function lab_syntax(c: connection, text: string, location: string)
    {
    local s = to_lower(text);
    local script_tag = /(<|%3c)script(>|%3e|[+[:space:]])/ in s;
    local event_tag = /(<|%3c)(img|svg|body|iframe)/ in s && /(onerror|onload)([+[:space:]]|%20)*(=|%3d)/ in s;
    if ( script_tag || event_tag )
        emit(c,"LABV2/HTTP_XSS_SYNTAX",1,0sec,0sec,fmt("bounded plaintext HTTP %s executable tag/event syntax; intent indicator, not exploit success",location));
    local quote = /(%27|%22|'|\x22)/ in s;
    local sql_comment = /(--|%2d%2d|%23|#)/ in s;
    local boolean_sql = /(^|[+[:space:]])or([+[:space:]]|%20)+/ in s && /(=|%3d)/ in s;
    local union_sql = /union([+[:space:]]|%20)+(all([+[:space:]]|%20)+)?select([+[:space:]]|%20)+/ in s;
    local login_comment = /(^|[?&])(username|user|login)=/ in s && quote && sql_comment;
    if ( quote && ((boolean_sql && sql_comment) || union_sql || login_comment) )
        emit(c,"LABV2/HTTP_SQL_SYNTAX",1,0sec,0sec,fmt("bounded plaintext HTTP %s quote plus SQL expression/comment syntax; intent indicator only",location));
    }
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    lab_method[c$uid] = method;
    lab_body[c$uid] = "";
    if ( c$uid in lab_gap ) delete lab_gap[c$uid];
    lab_syntax(c,unescaped_URI,"URI");
    }
event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( !is_orig || c$uid !in lab_method || lab_method[c$uid] != "POST" ) return;
    if ( c$uid !in lab_body ) lab_body[c$uid] = "";
    local remaining: count = 8192 - |lab_body[c$uid]|;
    if ( remaining > 0 ) lab_body[c$uid] += sub_bytes(data,1,remaining);
    }
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
    {
    if ( !is_orig ) return;
    if ( c$uid in lab_method && lab_method[c$uid] == "POST" && c$uid in lab_body &&
         c$uid !in lab_gap && !stat$interrupted && stat$content_gap_length == 0 )
        lab_syntax(c,lab_body[c$uid],"POST body first8192bytes");
    if ( c$uid in lab_body ) delete lab_body[c$uid];
    if ( c$uid in lab_method ) delete lab_method[c$uid];
    }
event content_gap(c: connection, is_orig: bool, seq: count, length: count)
    { if ( is_orig ) add lab_gap[c$uid]; }
event connection_state_remove(c: connection)
    {
    if ( c$uid in lab_body ) delete lab_body[c$uid];
    if ( c$uid in lab_method ) delete lab_method[c$uid];
    if ( c$uid in lab_gap ) delete lab_gap[c$uid];
    }