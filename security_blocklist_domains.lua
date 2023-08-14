-- listen on localhost
setLocal("0.0.0.0:53", {})
webserver("0.0.0.0:8080")
setWebserverConfig({acl="0.0.0.0/0", password="open", apiKey="open", hashPlaintextCredentials=true, apiRequiresAuthentication=false})

-- backend dns
newServer({address = "1.1.1.1:53", pool="default"})


local blackholeDomains = newSuffixMatchNode()

local function onRegisterDomain(dq)
    if blackholeDomains:check(dq.qname) then
        infolog("removing domain: " ..  dq.qname:toString() .. " from blacklist")
        blackholeDomains:remove(dq.qname)
    else
        infolog("blacklisting domain: " ..  dq.qname:toString())
        blackholeDomains:add(dq.qname)
    end
    return DNSAction.Spoof, "success"
end

local function onBlacklistDomain(dq)
    if blackholeDomains:check(dq.qname) then
        return DNSAction.Refused
    else
        return DNSAction.None, ""      -- no action
    end
end

-- register domain to blacklist from the DNS notify
-- dig @127.0.0.1 -p 5553 +opcode=notify +tcp google.com
addAction(OpcodeRule(DNSOpcode.Notify), LuaAction(onRegisterDomain))

-- Refused all domains blacklisted
addAction(AllRule(), LuaAction(onBlacklistDomain))

-- default rule
addAction( AllRule(), PoolAction("default"))