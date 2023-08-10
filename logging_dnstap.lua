-- dnstap logging for dns traffic, can be used with the remote logger like https://github.com/dmachard/go-dnscollector

-- listen on localhost
setLocal("0.0.0.0:53", {})
-- backend dns
newServer({address = "1.1.1.1:53", pool="default"})

-- init remote logger 
tap_logging = newFrameStreamTcpLogger("192.168.1.20:6000")

-- log all queries
addAction(AllRule(), DnstapLogAction("dnsdist_server", tap_logging))

-- log all replies
addResponseAction(AllRule(), DnstapLogResponseAction("dnsdist_server", tap_logging))

-- log all replies from cache
addCacheHitResponseAction(AllRule(), DnstapLogResponseAction("dnsdist_server", tap_logging))

-- default rule
addAction( AllRule(), PoolAction("default"))