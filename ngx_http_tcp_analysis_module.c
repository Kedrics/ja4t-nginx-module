#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>         /* Add this for MD5 functions */
#include <netinet/tcp.h>      /* For TCP_INFO */
#include <netinet/ip.h>       /* For IP headers */
#include <yaml.h>
struct tcp_info_l {
    __u8    tcpi_state;
    __u8    tcpi_ca_state;
    __u8    tcpi_retransmits;
    __u8    tcpi_probes;
    __u8    tcpi_backoff;
    __u8    tcpi_options;
    __u8    tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
    __u8    tcpi_delivery_rate_app_limited:1, tcpi_fastopen_client_fail:2;

    __u32   tcpi_rto;
    __u32   tcpi_ato;
    __u32   tcpi_snd_mss;
    __u32   tcpi_rcv_mss;

    __u32   tcpi_unacked;
    __u32   tcpi_sacked;
    __u32   tcpi_lost;
    __u32   tcpi_retrans;
    __u32   tcpi_fackets;

    /* Times. */
    __u32   tcpi_last_data_sent;
    __u32   tcpi_last_ack_sent;     /* Not remembered, sorry. */
    __u32   tcpi_last_data_recv;
    __u32   tcpi_last_ack_recv;

    /* Metrics. */
    __u32   tcpi_pmtu;
    __u32   tcpi_rcv_ssthresh;
    __u32   tcpi_rtt;
    __u32   tcpi_rttvar;
    __u32   tcpi_snd_ssthresh;
    __u32   tcpi_snd_cwnd;
    __u32   tcpi_advmss;
    __u32   tcpi_reordering;

    __u32   tcpi_rcv_rtt;
    __u32   tcpi_rcv_space;

    __u32   tcpi_total_retrans;

    __u64   tcpi_pacing_rate;
    __u64   tcpi_max_pacing_rate;
    __u64   tcpi_bytes_acked;    /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
    __u64   tcpi_bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
    __u32   tcpi_segs_out;       /* RFC4898 tcpEStatsPerfSegsOut */
    __u32   tcpi_segs_in;        /* RFC4898 tcpEStatsPerfSegsIn */

    __u32   tcpi_notsent_bytes;
    __u32   tcpi_min_rtt;
    __u32   tcpi_data_segs_in;      /* RFC4898 tcpEStatsDataSegsIn */
    __u32   tcpi_data_segs_out;     /* RFC4898 tcpEStatsDataSegsOut */

    __u64   tcpi_delivery_rate;
    
    __u64   tcpi_busy_time;      /* Time (usec) busy sending data */
    __u64   tcpi_rwnd_limited;   /* Time (usec) limited by receive window */
    __u64   tcpi_sndbuf_limited; /* Time (usec) limited by send buffer */

    __u32   tcpi_delivered;
    __u32   tcpi_delivered_ce;

    __u64   tcpi_bytes_sent;     /* RFC4898 tcpEStatsPerfHCDataOctetsOut */
    __u64   tcpi_bytes_retrans;  /* RFC4898 tcpEStatsPerfOctetsRetrans */
    __u32   tcpi_dsack_dups;     /* RFC4898 tcpEStatsStackDSACKDups */
    __u32   tcpi_reord_seen;     /* reordering events seen */

    __u32   tcpi_rcv_ooopack;    /* Out-of-order packets received */

    __u32   tcpi_snd_wnd;        /* peer's advertised receive window after
                                  * scaling (bytes)
                                  */
};
/* Define TCP_INFO options if not available */
#ifndef TCPI_OPT_TIMESTAMPS
#define TCPI_OPT_TIMESTAMPS 1
#endif

#ifndef TCPI_OPT_SACK
#define TCPI_OPT_SACK 2
#endif

#ifndef TCPI_OPT_ECN
#define TCPI_OPT_ECN 8
#endif

#ifndef TCPI_OPT_NOP
#define TCPI_OPT_NOP 16
#endif

typedef struct {
    ngx_array_t *tcp_analysis_signatures;  /* Array of ngx_str_t */
    ngx_str_t    log_path;
    ngx_flag_t   enabled;
} ngx_http_tcp_analysis_main_conf_t;

typedef struct {
    ngx_flag_t   enabled;
    ngx_msec_t   tls_rtt;
} ngx_http_tcp_analysis_loc_conf_t;

static void *ngx_http_tcp_analysis_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_tcp_analysis_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_tcp_analysis_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_tcp_analysis_yaml_config(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_tcp_analysis_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_tcp_analysis_handler(ngx_http_request_t *r);
static char *ngx_calc_tcp_analysis_hash(ngx_connection_t *c, u_char *hash_buf, size_t buf_size);
static ngx_int_t ngx_http_tcp_analysis_log_tcp_info(ngx_http_request_t *r, ngx_connection_t *c, const char *tcp_analysis_hash);

static ngx_command_t ngx_http_tcp_analysis_commands[] = {
    { ngx_string("tcp_analysis_enabled"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tcp_analysis_loc_conf_t, enabled),
      NULL },

    { ngx_string("tcp_analysis_config_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_tcp_analysis_yaml_config,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("tcp_analysis_log_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_tcp_analysis_main_conf_t, log_path),
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_tcp_analysis_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_http_tcp_analysis_init,                 /* postconfiguration */
    ngx_http_tcp_analysis_create_main_conf,     /* create main configuration */
    NULL,                               /* init main configuration */
    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */
    ngx_http_tcp_analysis_create_loc_conf,      /* create location configuration */
    ngx_http_tcp_analysis_merge_loc_conf        /* merge location configuration */
};

ngx_module_t ngx_http_tcp_analysis_module = {
    NGX_MODULE_V1,
    &ngx_http_tcp_analysis_module_ctx,          /* module context */
    ngx_http_tcp_analysis_commands,             /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_tcp_analysis_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_tcp_analysis_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_tcp_analysis_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->tcp_analysis_signatures = ngx_array_create(cf->pool, 10, sizeof(ngx_str_t));
    if (conf->tcp_analysis_signatures == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    
    return conf;
}

static void *
ngx_http_tcp_analysis_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_tcp_analysis_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_tcp_analysis_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->tls_rtt = 0;

    return conf;
}
static char *
ngx_http_tcp_analysis_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_tcp_analysis_loc_conf_t *prev = parent;
    ngx_http_tcp_analysis_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

    return NGX_CONF_OK;
}

static char *
ngx_http_tcp_analysis_yaml_config(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_tcp_analysis_main_conf_t *jmcf = conf;
    ngx_str_t *value;
    FILE *file;
    yaml_parser_t parser;
    yaml_token_t token;
    ngx_str_t *signature;
    
    value = cf->args->elts;
    
    file = fopen((const char *)value[1].data, "rb");
    if (file == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "failed to open tcp_analysis configuration file: %s", value[1].data);
        return NGX_CONF_ERROR;
    }
    
    if (!yaml_parser_initialize(&parser)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "failed to initialize YAML parser");
        fclose(file);
        return NGX_CONF_ERROR;
    }
    
    yaml_parser_set_input_file(&parser, file);
    
    int in_item = 0;
    
    do {
        yaml_parser_scan(&parser, &token);
        
        switch(token.type) {
            case YAML_SCALAR_TOKEN:
                if (in_item) {
                    /* This is a tcp_analysis signature value */
                    signature = ngx_array_push(jmcf->tcp_analysis_signatures);
                    if (signature == NULL) {
                        yaml_token_delete(&token);
                        yaml_parser_delete(&parser);
                        fclose(file);
                        return NGX_CONF_ERROR;
                    }
                    
                    signature->len = strlen((const char *)token.data.scalar.value);
                    signature->data = ngx_pnalloc(cf->pool, signature->len);
                    
                    if (signature->data == NULL) {
                        yaml_token_delete(&token);
                        yaml_parser_delete(&parser);
                        fclose(file);
                        return NGX_CONF_ERROR;
                    }
                    
                    ngx_memcpy(signature->data, token.data.scalar.value, signature->len);
                    in_item = 0;
                }
                break;
                
            case YAML_BLOCK_SEQUENCE_START_TOKEN:
                /* Start of the list of signatures */
                break;
                
            case YAML_BLOCK_ENTRY_TOKEN:
                /* New item in the list */
                in_item = 1;
                break;
                
            default:
                break;
        }
        
        if (token.type != YAML_STREAM_END_TOKEN) {
            yaml_token_delete(&token);
        }
        
    } while(token.type != YAML_STREAM_END_TOKEN);
    
    yaml_token_delete(&token);
    yaml_parser_delete(&parser);
    fclose(file);
    
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_tcp_analysis_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_tcp_analysis_handler;

    return NGX_OK;
}

static char *
ngx_calc_tcp_analysis_hash(ngx_connection_t *c, u_char *hash_buf, size_t buf_size)
{
    struct tcp_info_l tcp_info;
    socklen_t tcp_info_len = sizeof(tcp_info);
    char tcp_features[512];
    u_char hash[16];
    int ttl = 64; // Default TTL
    int window_size = 0;
    int mss = 0;
    int wscale = 0;
    int sack = 0;
    int timestamps = 0;
    int nop = 0;

    /* Ensure buffer is clean */
    ngx_memzero(hash_buf, buf_size);

    /* Get IP TTL */
    socklen_t ttl_len = sizeof(ttl);
    if (getsockopt(c->fd, IPPROTO_IP, IP_TTL, &ttl, &ttl_len) == -1) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0, "Failed to get IP_TTL, using default: %d", ttl);
    }

    /* Get TCP info if available */
    if (getsockopt(c->fd, IPPROTO_TCP, TCP_INFO, &tcp_info, &tcp_info_len) != -1) {
        window_size = tcp_info.tcpi_snd_wnd;
        mss = tcp_info.tcpi_snd_mss;
        wscale = tcp_info.tcpi_snd_wscale;
        sack = (tcp_info.tcpi_options & TCPI_OPT_SACK) ? 1 : 0;
        timestamps = (tcp_info.tcpi_options & TCPI_OPT_TIMESTAMPS) ? 1 : 0;
        nop = (tcp_info.tcpi_options & TCPI_OPT_NOP) ? 1 : 0;
    }

    /* Format TCP features with TTL */
    snprintf(tcp_features, sizeof(tcp_features), 
             "wscale=%d,sack=%d,tstamp=%d,nop=%d,mss=%d,window=%d,ttl=%d",
             wscale, sack, timestamps, nop, mss, window_size, ttl);

    /* Calculate MD5 hash */
    ngx_md5_t md5_ctx;
    ngx_md5_init(&md5_ctx);
    ngx_md5_update(&md5_ctx, (u_char *)tcp_features, strlen(tcp_features));
    ngx_md5_final(hash, &md5_ctx);

    /* Format the hash into hex */
    snprintf((char *)hash_buf, buf_size, "%02x%02x%02x%02x", 
             hash[0], hash[1], hash[2], hash[3]);

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0, "Raw hash buffer: %s", hash_buf);

    return (char *)hash_buf;
}

static ngx_int_t
ngx_http_tcp_analysis_log_tcp_info(ngx_http_request_t *r, ngx_connection_t *c, const char *tcp_analysis_hash)
{
    ngx_http_tcp_analysis_main_conf_t *jmcf;
    ngx_http_tcp_analysis_loc_conf_t  *jlcf;
    struct tcp_info_l tcp_info;
    socklen_t tcp_info_len = sizeof(tcp_info);
    u_char *p;
    size_t len, total_len;
    ngx_fd_t fd;
    time_t now;
    u_char time_buf[32];
    struct tm tm;

    jmcf = ngx_http_get_module_main_conf(r, ngx_http_tcp_analysis_module);
    jlcf = ngx_http_get_module_loc_conf(r, ngx_http_tcp_analysis_module);

    if (jmcf->log_path.len == 0) {
        return NGX_OK;
    }

    if (getsockopt(c->fd, IPPROTO_TCP, TCP_INFO, &tcp_info, &tcp_info_len) == -1) {
        ngx_log_error(NGX_LOG_ERR, c->log, errno, "Failed to get TCP_INFO for logging");
        return NGX_OK;
    }

    len = c->addr_text.len + 1024 + sizeof(time_buf);
    p = ngx_pcalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    total_len = 0;
    now = ngx_time();
    struct tm *tm_ptr = gmtime(&now);
    if (tm_ptr == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "gmtime failed");
        return NGX_ERROR;
    }
    tm = *tm_ptr;

    total_len += strftime((char *)time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm);
    total_len += snprintf((char *)p + total_len, len - total_len, "[%s] ", time_buf);

    if (total_len >= len) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Log buffer overflow at timestamp");
        return NGX_ERROR;
    }

    total_len += snprintf((char *)p + total_len, len - total_len, 
                          "IP: %.*s, tcp_analysis: %s", 
                          (int)c->addr_text.len, c->addr_text.data, tcp_analysis_hash);

    if (total_len >= len) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Log buffer overflow at IP/tcp_analysis");
        return NGX_ERROR;
    }

    int ttl = 64;
    socklen_t ttl_len = sizeof(ttl);
    if (getsockopt(c->fd, IPPROTO_IP, IP_TTL, &ttl, &ttl_len) != -1) {
        total_len += snprintf((char *)(p + total_len), len - total_len, 
                              ", TTL: %d", ttl);
    }

    if (total_len >= len) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Log buffer overflow at TTL");
        return NGX_ERROR;
    }

    total_len += snprintf((char *)(p + total_len), len - total_len, 
                          ", MSS: %d", tcp_info.tcpi_snd_mss);
    total_len += snprintf((char *)(p + total_len), len - total_len, 
                          ", Window: %d", tcp_info.tcpi_snd_wnd);
    total_len += snprintf((char *)(p + total_len), len - total_len, 
                          ", Wscale: %d", tcp_info.tcpi_snd_wscale);
    total_len += snprintf((char *)(p + total_len), len - total_len,
                          ", SACK: %d, Timestamps: %d, ECN: %d",
                          (tcp_info.tcpi_options & TCPI_OPT_SACK) ? 1 : 0,
                          (tcp_info.tcpi_options & TCPI_OPT_TIMESTAMPS) ? 1 : 0,
                          (tcp_info.tcpi_options & TCPI_OPT_ECN) ? 1 : 0);
    total_len += snprintf((char *)(p + total_len), len - total_len, 
                          ", TCP_RTT: %uus", tcp_info.tcpi_rtt);

    if (total_len >= len) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Log buffer overflow at TCP info");
        return NGX_ERROR;
    }

    // Log TLS RTT
    if (c->ssl && jlcf->tls_rtt > 0) {
        total_len += snprintf((char *)(p + total_len), len - total_len, 
                              ", TLS_RTT: %luus", (unsigned long)jlcf->tls_rtt);
    } else {
        total_len += snprintf((char *)(p + total_len), len - total_len, 
                              ", TLS_RTT: N/A");
    }

    if (total_len >= len) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Log buffer overflow at TLS info");
        return NGX_ERROR;
    }

    total_len += snprintf((char *)(p + total_len), len - total_len, "\n");

    if (total_len >= len) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Log buffer overflow at newline");
        return NGX_ERROR;
    }

    fd = ngx_open_file(jmcf->log_path.data, NGX_FILE_APPEND, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, c->log, errno, "Failed to open tcp_analysis log file: %V", &jmcf->log_path);
        return NGX_ERROR;
    }

    ssize_t written = ngx_write_fd(fd, p, total_len);
    if (written == NGX_ERROR || (size_t)written != total_len) {
        ngx_log_error(NGX_LOG_ERR, c->log, errno, "Failed to write full tcp_analysis log: wrote %z of %z bytes", written, total_len);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    ngx_close_file(fd);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0, "tcp_analysis log: %s", p);

    return NGX_OK;
}
static ngx_int_t
ngx_http_tcp_analysis_handler(ngx_http_request_t *r)
{
    ngx_http_tcp_analysis_loc_conf_t   *jlcf;
    ngx_http_tcp_analysis_main_conf_t  *jmcf;
    ngx_str_t                  *signature;
    ngx_uint_t                   i;
    u_char                      tcp_analysis_hash_buf[9];
    char                       *tcp_analysis_hash;

    jlcf = ngx_http_get_module_loc_conf(r, ngx_http_tcp_analysis_module);
    jmcf = ngx_http_get_module_main_conf(r, ngx_http_tcp_analysis_module);

    if (!jlcf->enabled) {
        return NGX_DECLINED;
    }

    tcp_analysis_hash = ngx_calc_tcp_analysis_hash(r->connection, tcp_analysis_hash_buf, sizeof(tcp_analysis_hash_buf));
    if (tcp_analysis_hash == NULL) {
        return NGX_DECLINED;
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Calculated tcp_analysis hash: %s", tcp_analysis_hash);

    // Calculate TLS RTT if this is an SSL connection
    if (r->connection->ssl) {
        ngx_msec_t start_time = r->connection->start_time; // Milliseconds since epoch
        ngx_msec_t end_time;

        ngx_time_update(); // Update NGINX's time
        end_time = ngx_current_msec; // Current time in milliseconds

        // Calculate TLS RTT in microseconds
        jlcf->tls_rtt = (end_time - start_time) * 1000; // Convert ms to us
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                      "TLS RTT: %uMus (start: %Mms, end: %Mms)", 
                      jlcf->tls_rtt, start_time, end_time);
    } else {
        jlcf->tls_rtt = 0; // No TLS RTT for non-SSL connections
    }

    ngx_http_tcp_analysis_log_tcp_info(r, r->connection, tcp_analysis_hash);

    signature = jmcf->tcp_analysis_signatures->elts;
    for (i = 0; i < jmcf->tcp_analysis_signatures->nelts; i++) {
        if (signature[i].len == 8 && 
            ngx_strncmp(tcp_analysis_hash, signature[i].data, 8) == 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                         "Blocked connection from %V with tcp_analysis hash: %s",
                         &r->connection->addr_text, tcp_analysis_hash);
            return NGX_HTTP_FORBIDDEN;
        }
    }

    return NGX_DECLINED;
}
