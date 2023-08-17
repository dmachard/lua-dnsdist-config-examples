-- listen on localhost
setLocal("0.0.0.0:53", {})
newServer({address = "1.1.1.1:53", pool="default"})

-- blacklist part
local blocking_duration = 60 -- in seconds
blacklistedIPs=TimedIPSetRule()

local function onRegisterIP(dq)
    infolog("blacklisting IP: " .. dq.qname:toStringNoDot() .. " during " .. blocking_duration .. " seconds")
    blacklistedIPs:add(newCA(dq.qname:toStringNoDot()), blocking_duration)
    return DNSAction.Spoof, "success"
end

-- register the IP address to blacklist from the Notify
-- dig @127.0.0.1 -p 5553 +opcode=notify +tcp 172.17.0.1
addAction(OpcodeRule(DNSOpcode.Notify), LuaAction(onRegisterIP))

-- Refused all IP addresses blacklisted
addAction(blacklistedIPs:slice(), RCodeAction(DNSRCode.REFUSED))

-- default rule
addAction( AllRule(), PoolAction("default"))