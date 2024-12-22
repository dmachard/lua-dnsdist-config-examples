-- listen on localhost
setLocal("0.0.0.0:53", {})

-- init backend
newServer({address = "1.1.1.1:53", pool="default"})

-- init dnstap remote collector
rl = newFrameStreamTcpLogger("192.168.1.16:6000")

local uniqID = nil

function generateID()
  return string.format("%08x%08x", math.random(0, 2^32 - 1), math.random(0, 2^32 - 1))
end

function addUniqID(dq)
  uniqID = generateID()
  dq:setEDNSOption(65001, uniqID)
  infolog("Generated and uniqID: " .. uniqID)
  return DNSAction.None
end

function alterDnstapQuery(dq, tap)
  tap:setExtra(uniqID)
end

function alterDnstapResponse(dr, tap)
  tap:setExtra(uniqID)
end

function alterDnstapCachedResponse(dr, tap)
  tap:setExtra(uniqID)
end

-- rules for queries
addAction(AllRule(), LuaAction(addUniqID))
addAction(AllRule(), DnstapLogAction("dnsdist", rl, alterDnstapQuery))
addAction( AllRule(), PoolAction("default"))

-- rules for replies
addCacheHitResponseAction(AllRule(), DnstapLogResponseAction("dnsdist", rl, alterDnstapCachedResponse))
addResponseAction(AllRule(), DnstapLogResponseAction("dnsdist", rl, alterDnstapResponse))
