-- dnstap logging for dns traffic, can be used with the remote logger like https://github.com/dmachard/go-dnscollector

-- listen on localhost
setLocal("0.0.0.0:53", {})
-- backend dns
newServer({address = "1.1.1.1:53", pool="default"})


-- init remote logger 
protobuf_logging = newRemoteLogger("192.168.1.20:6000")

-- log all queries
addAction(AllRule(), RemoteLogAction(protobuf_logging, nil, {serverID="dnsdist_server"}))

-- log all replies
addResponseAction(AllRule(), RemoteLogResponseAction(protobuf_logging, nil, true, {serverID="dnsdist_server"}))

-- log all replies from cache
addCacheHitResponseAction(AllRule(), RemoteLogResponseAction(protobuf_logging, nil, true, {serverID="dnsdist_server"}))


-- default rule
addAction( AllRule(), PoolAction("default"))