-- listen on localhost
setLocal("0.0.0.0:53", {})
webserver("0.0.0.0:8080")
setWebserverConfig({acl="0.0.0.0/0", password="open", apiKey="open", hashPlaintextCredentials=true, apiRequiresAuthentication=false})

-- backend dns
newServer({address = "1.1.1.1:53", pool="default"})

local blacklistedDomains = {}

local function onRegisterDomain(dq)
    infolog("blacklisting the domain: " ..  dq.qname:toString())
    if blacklistedDomains[ dq.qname:toString()] ~= nil then
        blacklistedDomains[ dq.qname:toString()] = nil
     else
        blacklistedDomains[ dq.qname:toString()] = 1
     end
    return DNSAction.Spoof, "success"
end

local function onBlacklistDomain(dq)
    if blacklistedDomains[ dq.qname:toString()] ~= nil then
        return DNSAction.Refused
    else
        return DNSAction.None, ""      -- no action
    end
end

-- register domain to blacklist from the DNS notify
-- dig @127.0.0.1 -p 5553 +opcode=update +tcp google.com
addAction(OpcodeRule(DNSOpcode.Notify), LuaAction(onRegisterDomain))

-- Refused all domains blacklisted
addAction(AllRule(), LuaAction(onBlacklistDomain))

-- default rule
addAction( AllRule(), PoolAction("default"))