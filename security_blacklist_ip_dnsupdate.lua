-- listen on localhost
setLocal("0.0.0.0:53", {})
newServer({address = "1.1.1.1:53", pool="default"})

-- blacklist IP code part begin, this code requires dnsdist 1.8 minimum
blacklistedIPs=TimedIPSetRule()

-- convert bytes IP to IPv4 string format
function convertToIPv4(ip_bytes)
    local ipv4_string = ""
    for i = 1, #ip_bytes do
        ipv4_string = ipv4_string .. string.byte(ip_bytes:sub(i, i))
        if i < #ip_bytes then
            ipv4_string = ipv4_string .. "."
        end
    end
    return ipv4_string
end

-- convert bytes IP to IPv6 string format
function convertToIPv6(ip_bytes)
    local ipv6_string = ""
    for i = 1, #ip_bytes, 2 do
        local hex_bytes = string.format("%02X%02X", ip_bytes:byte(i), ip_bytes:byte(i+1))
        ipv6_string = ipv6_string .. hex_bytes
        if i < #ip_bytes-1 then
            ipv6_string = ipv6_string .. ":"
        end
    end
    return ipv6_string
end

-- Parse the DNS UPDATE query to get IP addresses to block
function onRegisterIP(dq)
    local packet = dq:getContent()

    local overlay = newDNSPacketOverlay(packet)
    local countRecords = overlay:getRecordsCountInSection(DNSSection.Authority)
    
    if countRecords == 0 then
        errlog("blacklist error: invalid dns update")
        return DNSAction.ServFail, ""
    end

    for idx=0, countRecords-1 do
        local record = overlay:getRecord(idx)
        local ip_string = ""
        ip_bytes = string.sub(packet, record.contentOffset+1, record.contentOffset+record.contentLength)

        -- ip4 record
        if record.type == 1 then
            ip_string = convertToIPv4(ip_bytes)
        end
        -- ip6 record
        if record.type == 28 then
            ip_string = convertToIPv6(ip_bytes)
        end

        if ip_string == "0.0.0.0" and record.ttl == 0 then
            infolog("reset all blacklisted ips")
            blacklistedIPs:clear()
        else
            infolog("blacklisting IP: " .. ip_string .. " during " .. record.ttl .. " seconds")
        end
        blacklistedIPs:add(newCA(ip_string), record.ttl)
    end

    -- turn query in reply on success
    dq.dh:setQR(true)
    return DNSAction.HeaderModify, ""
end

-- register the IP address to blacklist with DNS UPDATE
-- to block IP during 60s: ./blockip_nsupdate.sh 172.17.0.1 60
-- to unblock all IPs: ./blockip_nsupdate.sh 0.0.0.0 0
addAction(AndRule({makeRule("blockip.local.dev"), OpcodeRule(DNSOpcode.Update)}), LuaAction(onRegisterIP))

-- Refused all IP addresses blacklisted
addAction(blacklistedIPs:slice(), RCodeAction(DNSRCode.REFUSED))

-- default rule
addAction( AllRule(), PoolAction("default"))