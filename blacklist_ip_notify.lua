-- listen on localhost
setLocal("0.0.0.0:53", {})
-- backend dns
newServer({address = "1.1.1.1:53", pool="default"})

local blocking_duration = 60 -- in seconds

blacklistedIPs=TimedIPSetRule()
addAction(blacklistedIPs:slice(), RCodeAction(DNSRCode.REFUSED))

local function blacklistIP(dq)
    infolog(dq.remoteaddr:toString())
    infolog("blacklisting " .. dq.qname:toStringNoDot())
    blacklistedIPs:add(newCA(dq.qname:toStringNoDot()), blocking_duration)
    return DNSAction.Spoof, "success"
end

-- blacklist ip on notify
-- dig @127.0.0.1 -p 5553 +opcode=notify +tcp 172.17.0.1
addAction(OpcodeRule(DNSOpcode.Notify), LuaAction(blacklistIP))

-- default rule
addAction( AllRule(), PoolAction("default"))