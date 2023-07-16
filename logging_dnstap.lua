-- dnstap logging for dns traffic, can be used with the remote logger like https://github.com/dmachard/go-dnscollector

-- init remote logger 
tap_logging = newFrameStreamTcpLogger("192.168.1.20:6000")

-- log all queries
addAction(rule_intra,DnstapLogAction("dnsdist_server", tap_logging))

-- log all replies
addResponseAction(rule_intra,DnstapLogResponseAction("dnsdist_server", tap_logging))

-- log all replies from cache
addCacheHitResponseAction(rule_intra, DnstapLogResponseAction("dnsdist_server", tap_logging))
