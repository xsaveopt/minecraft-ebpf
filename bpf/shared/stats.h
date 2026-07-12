#ifndef __MINECRAFT_STATS_H__
#define __MINECRAFT_STATS_H__

enum minecraft_stat {
    STAT_PASS_TCP                       = 0,
    STAT_TCP_ESTABLISHED_INSERTS        = 1,
    STAT_TCP_L7_PROMOTED                = 2,
    STAT_TCP_L7_MATCH_NO_EST            = 3,
    STAT_TCP_HANDSHAKE_STATUS_SEEN      = 4,
    STAT_TCP_HANDSHAKE_LOGIN_SEEN       = 5,
    STAT_DROP_TCP_NO_SYN                = 6,
    STAT_DROP_TCP_TOO_MANY_OPEN         = 7,
    STAT_DROP_TCP_GLOBAL_RATELIMIT      = 8,
    STAT_DROP_STATUS_RATELIMIT          = 9,
    STAT_DROP_LOGIN_RATELIMIT           = 10,
    STAT_DROP_MALFORMED_HANDSHAKE       = 11,
    STAT_DROP_TCP_UNHEALTHY             = 12,
    STAT_DROP_TCP_BAD_FLAGS             = 13,
    STAT_DROP_CONN_RATELIMIT            = 14,
    STAT_DROP_TCP_CONN_RATE             = 15,
    STAT_MAX                            = 16,
};

#endif
