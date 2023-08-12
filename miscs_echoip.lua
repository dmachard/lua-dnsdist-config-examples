setLocal("0.0.0.0:53", {})
newServer({address = "1.1.1.1:53"})

-- Echo capability of ip address from domain name for development
local function onEchoIpAddress(dq)
        -- list of regexs to find ip in qname
        ipsregex = {}

        -- 10.0.0.1.local.dev maps to A 10.0.0.1
        -- 192-168-1-250.local.dev maps to A 192.168.1.250
        ipsregex.ip4  = "^(%d+[%.-]%d+[%.-]%d+[%.-]%d+)%."

        -- app.10.8.0.1.local.dev maps to A 10.8.0.1
        -- app-116-203-255-68.local.dev maps to A 116.203.255.68
        -- customer1.app.10.0.0.1.local.dev maps to A 10.0.0.1
        -- customer-app1-127-0-0-1.local.dev maps to A 127.0.0.1
        ipsregex.ip4name = "[^a-z0-9A-Z]%.?(%d+[%.-]%d+[%.-]%d+[%.-]%d+)%."

        -- 0a000803.local.dev maps to A 10.0.8.3
        ipsregex.ip4hex = "^([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F])%."

        -- app-c0a801fc.local.dev maps to A 192.168.1.252
        -- customer3-app-7f000101.local.dev maps to 127.0.1.1
        ipsregex.ip4hexname = "[^a-z0-9A-Z]%.?([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F])%."

        -- default ip to return on no matched
        local retip = "127.0.0.2"

        -- iter over each regex to find ip
        for k, pattern in pairs(ipsregex) do
           addr  = string.match(dq.qname:toString(), pattern)
           if addr then
             retip = string.gsub(addr, "-", ".")

             if k == "ip4hex" or k == "ip4hexname" then
                retip = tonumber(retip, 16)
             end

             break
           end
        end

        return DNSAction.Spoof, retip
end

addAction("local.dev.", LuaAction(onEchoIpAddress))

-- default rule
addAction( AllRule(), PoolAction("default"))
