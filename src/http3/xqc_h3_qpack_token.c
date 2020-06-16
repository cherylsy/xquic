#include <stdlib.h>
#include <stdio.h>
#include "src/http3/xqc_h3_qpack_token.h"
#include "src/http3/xqc_h3_qpack.h"

ssize_t xqc_g_static_token_index[XQC_QPACK_TOKEN_MAX_SIZE];
xqc_qpack_static_table_entry xqc_g_static_table[] =
{
    {":authority", "", 10, 0,},
    {":path", "/", 5, 1,},
    {"age", "0", 3, 1,},
    {"content-disposition", "", 19, 0,},
    {"content-length", "0", 14, 1,},
    {"cookie", "", 6, 0,},
    {"date", "", 4, 0,},
    {"etag", "", 4, 0,},
    {"if-modified-since", "", 17, 0,},
    {"if-none-match", "", 13, 0,},
    {"last-modified", "", 13, 0,},
    {"link", "", 4, 0,},
    {"location", "", 8, 0,},
    {"referer", "", 7, 0,},
    {"set-cookie", "", 10, 0,},
    {":method", "CONNECT", 7, 7,},
    {":method", "DELETE", 7, 6,},
    {":method", "GET", 7, 3,},
    {":method", "HEAD", 7, 4,},
    {":method", "OPTIONS", 7, 7,},
    {":method", "POST", 7, 4,},
    {":method", "PUT", 7, 3,},
    {":scheme", "http", 7, 4,},
    {":scheme", "https", 7, 5,},
    {":status", "103", 7, 3,},
    {":status", "200", 7, 3,},
    {":status", "304", 7, 3,},
    {":status", "404", 7, 3,},
    {":status", "503", 7, 3,},
    {"accept", "*/*", 6, 3,},
    {"accept", "application/dns-message", 6, 23,},
    {"accept-encoding", "gzip, deflate, br", 15, 17,},
    {"accept-ranges", "bytes", 13, 5,},
    {"access-control-allow-headers", "cache-control", 28, 13,},
    {"access-control-allow-headers", "content-type", 28, 12,},
    {"access-control-allow-origin", "*", 27, 1,},
    {"cache-control", "max-age=0", 13, 9,},
    {"cache-control", "max-age=2592000", 13, 15,},
    {"cache-control", "max-age=604800", 13, 14,},
    {"cache-control", "no-cache", 13, 8,},
    {"cache-control", "no-store", 13, 8,},
    {"cache-control", "public, max-age=31536000", 13, 24,},
    {"content-encoding", "br", 16, 2,},
    {"content-encoding", "gzip", 16, 4,},
    {"content-type", "application/dns-message", 12, 23,},
    {"content-type", "application/javascript", 12, 22,},
    {"content-type", "application/json", 12, 16,},
    {"content-type", "application/x-www-form-urlencoded", 12, 33,},
    {"content-type", "image/gif", 12, 9,},
    {"content-type", "image/jpeg", 12, 10,},
    {"content-type", "image/png", 12, 9,},
    {"content-type", "text/css", 12, 8,},
    {"content-type", "text/html; charset=utf-8", 12, 24,},
    {"content-type", "text/plain", 12, 10,},
    {"content-type", "text/plain;charset=utf-8", 12, 24,},
    {"range", "bytes=0-", 5, 8,},
    {"strict-transport-security", "max-age=31536000", 25, 16,},
    {"strict-transport-security", "max-age=31536000; includesubdomains", 25, 35,},
    {"strict-transport-security", "max-age=31536000; includesubdomains; preload", 25, 44,},
    {"vary", "accept-encoding", 4, 15,},
    {"vary", "origin", 4, 6,},
    {"x-content-type-options", "nosniff", 22, 7,},
    {"x-xss-protection", "1; mode=block", 16, 13,},
    {":status", "100", 7, 3,},
    {":status", "204", 7, 3,},
    {":status", "206", 7, 3,},
    {":status", "302", 7, 3,},
    {":status", "400", 7, 3,},
    {":status", "403", 7, 3,},
    {":status", "421", 7, 3,},
    {":status", "425", 7, 3,},
    {":status", "500", 7, 3,},
    {"accept-language", "", 15, 0,},
    {"access-control-allow-credentials", "FALSE", 32, 5,},
    {"access-control-allow-credentials", "TRUE", 32, 4,},
    {"access-control-allow-headers", "*", 28, 1,},
    {"access-control-allow-methods", "get", 28, 3,},
    {"access-control-allow-methods", "get, post, options", 28, 18,},
    {"access-control-allow-methods", "options", 28, 7,},
    {"access-control-expose-headers", "content-length", 29, 14,},
    {"access-control-request-headers", "content-type", 30, 12,},
    {"access-control-request-method", "get", 29, 3,},
    {"access-control-request-method", "post", 29, 4,},
    {"alt-svc", "clear", 7, 5,},
    {"authorization", "", 13, 0,},
    {"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'", 23, 53,},
    {"early-data", "1", 10, 1,},
    {"expect-ct", "", 9, 0,},
    {"forwarded", "", 9, 0,},
    {"if-range", "", 8, 0,},
    {"origin", "", 6, 0,},
    {"purpose", "prefetch", 7, 8,},
    {"server", "", 6, 0,},
    {"timing-allow-origin", "*", 19, 1,},
    {"upgrade-insecure-requests", "1", 25, 1,},
    {"user-agent", "", 10, 0,},
    {"x-forwarded-for", "", 15, 0,},
    {"x-frame-options", "deny", 15, 4,},
    {"x-frame-options", "sameorigin", 15, 10,},
};


size_t xqc_get_qpack_static_table_size(){
    return sizeof(xqc_g_static_table)/sizeof(xqc_qpack_static_table_entry);
}

xqc_qpack_static_table_entry * xqc_get_qpack_static_table_entry(int idx){
    if(idx < 0 || idx >= xqc_get_qpack_static_table_size()){
        return NULL;
    }
    return &xqc_g_static_table[idx];
}

ssize_t xqc_get_qpack_token_index_value(int token){

    return xqc_g_static_token_index[token];
}

int xqc_qpack_lookup_token(const uint8_t *name, size_t namelen) {
  switch (namelen) {
  case 2:
    switch (name[1]) {
    case 'e':
      if (xqc_memeq("t", name, 1)) {
        return XQC_HTTP3_QPACK_TOKEN_TE;
      }
      break;
    }
    break;
  case 3:
    switch (name[2]) {
    case 'e':
      if (xqc_memeq("ag", name, 2)) {
        return XQC_HTTP3_QPACK_TOKEN_AGE;
      }
      break;
    }
    break;
  case 4:
    switch (name[3]) {
    case 'e':
      if (xqc_memeq("dat", name, 3)) {
        return XQC_HTTP3_QPACK_TOKEN_DATE;
      }
      break;
    case 'g':
      if (xqc_memeq("eta", name, 3)) {
        return XQC_HTTP3_QPACK_TOKEN_ETAG;
      }
      break;
    case 'k':
      if (xqc_memeq("lin", name, 3)) {
        return XQC_HTTP3_QPACK_TOKEN_LINK;
      }
      break;
    case 't':
      if (xqc_memeq("hos", name, 3)) {
        return XQC_HTTP3_QPACK_TOKEN_HOST;
      }
      break;
    case 'y':
      if (xqc_memeq("var", name, 3)) {
        return XQC_HTTP3_QPACK_TOKEN_VARY;
      }
      break;
    }
    break;
  case 5:
    switch (name[4]) {
    case 'e':
      if (xqc_memeq("rang", name, 4)) {
        return XQC_HTTP3_QPACK_TOKEN_RANGE;
      }
      break;
    case 'h':
      if (xqc_memeq(":pat", name, 4)) {
        return XQC_HTTP3_QPACK_TOKEN__PATH;
      }
      break;
    }
    break;
  case 6:
    switch (name[5]) {
    case 'e':
      if (xqc_memeq("cooki", name, 5)) {
        return XQC_HTTP3_QPACK_TOKEN_COOKIE;
      }
      break;
    case 'n':
      if (xqc_memeq("origi", name, 5)) {
        return XQC_HTTP3_QPACK_TOKEN_ORIGIN;
      }
      break;
    case 'r':
      if (xqc_memeq("serve", name, 5)) {
        return XQC_HTTP3_QPACK_TOKEN_SERVER;
      }
      break;
    case 't':
      if (xqc_memeq("accep", name, 5)) {
        return XQC_HTTP3_QPACK_TOKEN_ACCEPT;
      }
      break;
    }
    break;
  case 7:
    switch (name[6]) {
    case 'c':
      if (xqc_memeq("alt-sv", name, 6)) {
        return XQC_HTTP3_QPACK_TOKEN_ALT_SVC;
      }
      break;
    case 'd':
      if (xqc_memeq(":metho", name, 6)) {
        return XQC_HTTP3_QPACK_TOKEN__METHOD;
      }
      break;
    case 'e':
      if (xqc_memeq(":schem", name, 6)) {
        return XQC_HTTP3_QPACK_TOKEN__SCHEME;
      }
      if (xqc_memeq("purpos", name, 6)) {
        return XQC_HTTP3_QPACK_TOKEN_PURPOSE;
      }
      if (xqc_memeq("upgrad", name, 6)) {
        return XQC_HTTP3_QPACK_TOKEN_UPGRADE;
      }
      break;
    case 'r':
      if (xqc_memeq("refere", name, 6)) {
        return XQC_HTTP3_QPACK_TOKEN_REFERER;
      }
      break;
    case 's':
      if (xqc_memeq(":statu", name, 6)) {
        return XQC_HTTP3_QPACK_TOKEN__STATUS;
      }
      break;
    }
    break;
  case 8:
    switch (name[7]) {
    case 'e':
      if (xqc_memeq("if-rang", name, 7)) {
        return XQC_HTTP3_QPACK_TOKEN_IF_RANGE;
      }
      break;
    case 'n':
      if (xqc_memeq("locatio", name, 7)) {
        return XQC_HTTP3_QPACK_TOKEN_LOCATION;
      }
      break;
    }
    break;
  case 9:
    switch (name[8]) {
    case 'd':
      if (xqc_memeq("forwarde", name, 8)) {
        return XQC_HTTP3_QPACK_TOKEN_FORWARDED;
      }
      break;
    case 'l':
      if (xqc_memeq(":protoco", name, 8)) {
        return XQC_HTTP3_QPACK_TOKEN_PROTOCOL;
      }
      break;
    case 't':
      if (xqc_memeq("expect-c", name, 8)) {
        return XQC_HTTP3_QPACK_TOKEN_EXPECT_CT;
      }
      break;
    }
    break;
  case 10:
    switch (name[9]) {
    case 'a':
      if (xqc_memeq("early-dat", name, 9)) {
        return XQC_HTTP3_QPACK_TOKEN_EARLY_DATA;
      }
      break;
    case 'e':
      if (xqc_memeq("keep-aliv", name, 9)) {
        return XQC_HTTP3_QPACK_TOKEN_KEEP_ALIVE;
      }
      if (xqc_memeq("set-cooki", name, 9)) {
        return XQC_HTTP3_QPACK_TOKEN_SET_COOKIE;
      }
      break;
    case 'n':
      if (xqc_memeq("connectio", name, 9)) {
        return XQC_HTTP3_QPACK_TOKEN_CONNECTION;
      }
      break;
    case 't':
      if (xqc_memeq("user-agen", name, 9)) {
        return XQC_HTTP3_QPACK_TOKEN_USER_AGENT;
      }
      break;
    case 'y':
      if (xqc_memeq(":authorit", name, 9)) {
        return XQC_HTTP3_QPACK_TOKEN__AUTHORITY;
      }
      break;
    }
    break;
  case 12:
    switch (name[11]) {
    case 'e':
      if (xqc_memeq("content-typ", name, 11)) {
        return XQC_HTTP3_QPACK_TOKEN_CONTENT_TYPE;
      }
      break;
    }
    break;
  case 13:
    switch (name[12]) {
    case 'd':
      if (xqc_memeq("last-modifie", name, 12)) {
        return XQC_HTTP3_QPACK_TOKEN_LAST_MODIFIED;
      }
      break;
    case 'h':
      if (xqc_memeq("if-none-matc", name, 12)) {
        return XQC_HTTP3_QPACK_TOKEN_IF_NONE_MATCH;
      }
      break;
    case 'l':
      if (xqc_memeq("cache-contro", name, 12)) {
        return XQC_HTTP3_QPACK_TOKEN_CACHE_CONTROL;
      }
      break;
    case 'n':
      if (xqc_memeq("authorizatio", name, 12)) {
        return XQC_HTTP3_QPACK_TOKEN_AUTHORIZATION;
      }
      break;
    case 's':
      if (xqc_memeq("accept-range", name, 12)) {
        return XQC_HTTP3_QPACK_TOKEN_ACCEPT_RANGES;
      }
      break;
    }
    break;
  case 14:
    switch (name[13]) {
    case 'h':
      if (xqc_memeq("content-lengt", name, 13)) {
        return XQC_HTTP3_QPACK_TOKEN_CONTENT_LENGTH;
      }
      break;
    }
    break;
  case 15:
    switch (name[14]) {
    case 'e':
      if (xqc_memeq("accept-languag", name, 14)) {
        return XQC_HTTP3_QPACK_TOKEN_ACCEPT_LANGUAGE;
      }
      break;
    case 'g':
      if (xqc_memeq("accept-encodin", name, 14)) {
        return XQC_HTTP3_QPACK_TOKEN_ACCEPT_ENCODING;
      }
      break;
    case 'r':
      if (xqc_memeq("x-forwarded-fo", name, 14)) {
        return XQC_HTTP3_QPACK_TOKEN_X_FORWARDED_FOR;
      }
      break;
    case 's':
      if (xqc_memeq("x-frame-option", name, 14)) {
        return XQC_HTTP3_QPACK_TOKEN_X_FRAME_OPTIONS;
      }
      break;
    }
    break;
  case 16:
    switch (name[15]) {
    case 'g':
      if (xqc_memeq("content-encodin", name, 15)) {
        return XQC_HTTP3_QPACK_TOKEN_CONTENT_ENCODING;
      }
      break;
    case 'n':
      if (xqc_memeq("proxy-connectio", name, 15)) {
        return XQC_HTTP3_QPACK_TOKEN_PROXY_CONNECTION;
      }
      if (xqc_memeq("x-xss-protectio", name, 15)) {
        return XQC_HTTP3_QPACK_TOKEN_X_XSS_PROTECTION;
      }
      break;
    }
    break;
  case 17:
    switch (name[16]) {
    case 'e':
      if (xqc_memeq("if-modified-sinc", name, 16)) {
        return XQC_HTTP3_QPACK_TOKEN_IF_MODIFIED_SINCE;
      }
      break;
    case 'g':
      if (xqc_memeq("transfer-encodin", name, 16)) {
        return XQC_HTTP3_QPACK_TOKEN_TRANSFER_ENCODING;
      }
      break;
    }
    break;
  case 19:
    switch (name[18]) {
    case 'n':
      if (xqc_memeq("content-dispositio", name, 18)) {
        return XQC_HTTP3_QPACK_TOKEN_CONTENT_DISPOSITION;
      }
      if (xqc_memeq("timing-allow-origi", name, 18)) {
        return XQC_HTTP3_QPACK_TOKEN_TIMING_ALLOW_ORIGIN;
      }
      break;
    }
    break;
  case 22:
    switch (name[21]) {
    case 's':
      if (xqc_memeq("x-content-type-option", name, 21)) {
        return XQC_HTTP3_QPACK_TOKEN_X_CONTENT_TYPE_OPTIONS;
      }
      break;
    }
    break;
  case 23:
    switch (name[22]) {
    case 'y':
      if (xqc_memeq("content-security-polic", name, 22)) {
        return XQC_HTTP3_QPACK_TOKEN_CONTENT_SECURITY_POLICY;
      }
      break;
    }
    break;
  case 25:
    switch (name[24]) {
    case 's':
      if (xqc_memeq("upgrade-insecure-request", name, 24)) {
        return XQC_HTTP3_QPACK_TOKEN_UPGRADE_INSECURE_REQUESTS;
      }
      break;
    case 'y':
      if (xqc_memeq("strict-transport-securit", name, 24)) {
        return XQC_HTTP3_QPACK_TOKEN_STRICT_TRANSPORT_SECURITY;
      }
      break;
    }
    break;
  case 27:
    switch (name[26]) {
    case 'n':
      if (xqc_memeq("access-control-allow-origi", name, 26)) {
        return XQC_HTTP3_QPACK_TOKEN_ACCESS_CONTROL_ALLOW_ORIGIN;
      }
      break;
    }
    break;
  case 28:
    switch (name[27]) {
    case 's':
      if (xqc_memeq("access-control-allow-header", name, 27)) {
        return XQC_HTTP3_QPACK_TOKEN_ACCESS_CONTROL_ALLOW_HEADERS;
      }
      if (xqc_memeq("access-control-allow-method", name, 27)) {
        return XQC_HTTP3_QPACK_TOKEN_ACCESS_CONTROL_ALLOW_METHODS;
      }
      break;
    }
    break;
  case 29:
    switch (name[28]) {
    case 'd':
      if (xqc_memeq("access-control-request-metho", name, 28)) {
        return XQC_HTTP3_QPACK_TOKEN_ACCESS_CONTROL_REQUEST_METHOD;
      }
      break;
    case 's':
      if (xqc_memeq("access-control-expose-header", name, 28)) {
        return XQC_HTTP3_QPACK_TOKEN_ACCESS_CONTROL_EXPOSE_HEADERS;
      }
      break;
    }
    break;
  case 30:
    switch (name[29]) {
    case 's':
      if (xqc_memeq("access-control-request-header", name, 29)) {
        return XQC_HTTP3_QPACK_TOKEN_ACCESS_CONTROL_REQUEST_HEADERS;
      }
      break;
    }
    break;
  case 32:
    switch (name[31]) {
    case 's':
      if (xqc_memeq("access-control-allow-credential", name, 31)) {
        return XQC_HTTP3_QPACK_TOKEN_ACCESS_CONTROL_ALLOW_CREDENTIALS;
      }
      break;
    }
    break;
  }
  return XQC_HTTP3_QPACK_TOKEN_UNKNOWN;
}


int xqc_qpack_init_static_token_index(){
    int i = 0;
    for(i = 0; i < XQC_QPACK_TOKEN_MAX_SIZE; i++){
        xqc_g_static_token_index[i] = -1;
    }

    int static_table_len = sizeof(xqc_g_static_table)/sizeof(xqc_qpack_static_table_entry);
    for(i = 0; i < static_table_len; i++){

        xqc_qpack_static_table_entry * entry = &xqc_g_static_table[i];
        char * name = entry->name;
        size_t namelen = entry->name_len;

        int token = xqc_qpack_lookup_token(name, namelen);

        if(token == XQC_HTTP3_QPACK_TOKEN_UNKNOWN){ //means we lost static table options
            return -1;
        }
        if(xqc_g_static_token_index[token] == -1){
            xqc_g_static_token_index[token] = i;
        }
    }
    return 0;
}


