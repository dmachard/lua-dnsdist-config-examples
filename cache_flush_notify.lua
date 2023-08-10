-- listen on localhost
setLocal("0.0.0.0:53", {})
-- backend dns
newServer({address = "1.1.1.1:53", pool="default"})

-- return CNAME with flushed name
local function onNotifyFlush(dq)
        getPool("default"):getCache():expungeByName(dq.qname, DNSQType.ANY, true)
        return DNSAction.Spoof, "flushed"
end

-- flush domain entry on incoming notify
-- dig @127.0.0.1 google.fr +opcode=notify
addAction(OpcodeRule(DNSOpcode.Notify), LuaAction(onNotifyFlush))

-- default rule
addAction( AllRule(), PoolAction("default"))
