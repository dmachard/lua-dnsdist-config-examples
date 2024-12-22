addDOHLocal("0.0.0.0:443", "/etc/dnsdist/doh.crt", "/etc/dnsdist/doh.key", "/dns-query", {keepIncomingHeaders=true})
setACL({'0.0.0.0/0'})

newServer({address = "1.1.1.1", pool="poolA"})
newServer({address = "9.9.9.9", pool="poolB"})
newServer({address = "8.8.8.8", pool="poolB"})

function alterDnstapQuery(dq, tap)
  local ua = ""
  for key,value in pairs(dq:getHTTPHeaders()) do
    if key == 'user-agent' then
            ua = value
            break
    end
  end
  tap:setExtra(ua)
end

function alterDnstapResponse(dr, tap)
  tap:setExtra(dr.pool)
end

function alterDnstapCachedResponse(dr, tap)
  tap:setExtra("cached")
end

-- init dnstap remote collector
rl = newFrameStreamTcpLogger("192.168.1.17:6000")

-- rules for queries
addAction(AllRule(), DnstapLogAction("dnsdist1", rl, alterDnstapQuery))

addAction(ProbaRule(0.5), PoolAction("poolA"))
addAction(AllRule(), PoolAction("poolB"))

-- rules for replies
addCacheHitResponseAction(AllRule(), DnstapLogResponseAction("dnsdist1", rl, alterDnstapCachedResponse))
addResponseAction(AllRule(), DnstapLogResponseAction("dnsdist1", rl, alterDnstapResponse))
