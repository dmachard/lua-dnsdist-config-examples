-- Generic rules to block malicious dns traffic like DNS tunneling

-- listen on localhost
setLocal("0.0.0.0:53", {})
-- backend dns
newServer({address = "1.1.1.1:53", pool="default"})

-- remote security events logger based on dnstap
security_dnstap_logger = newFrameStreamTcpLogger("10.0.0.100:6000")

-- trusted domains to exclude
trusted_domains = newSuffixMatchNode()
trusted_domains:add(newDNSName("google.fr."))

-- blacklist ip during 60s
blacklistedIPs=TimedIPSetRule()
addAction(blacklistedIPs:slice(), RCodeAction(DNSRCode.REFUSED))

local ratelimited_ips = {}
local ratelimited_duration = 10 -- in seconds
local blocking_duration = 60 -- in seconds

local function blacklistIP(dq)
   blacklistedIPs:add(dq.remoteaddr, blocking_duration)
   return DNSAction.Refused
end

function countRateLimit(dq)
   local client_ip = dq.remoteaddr:toString()
   local now = os.time()
   if ratelimited_ips[client_ip] ~= nil then
      ratelimited_ips[client_ip].queries = ratelimited_ips[client_ip].queries + 1
   else
      ratelimited_ips[client_ip] = { queries = 1, timestamp = now, count = 0 }
   end
   return DNSAction.Drop
end

function maintenance()
  local now = os.time()
  for k, v in pairs(ratelimited_ips) do
        elapsed = now - v.timestamp
        qps = v.queries / elapsed
        if qps > 0 then
                v.count = v.count + 1
        end
        if elapsed >= ratelimited_duration then
                if v.count >= ratelimited_duration then
                        blacklistedIPs:add(newCA(k), blocking_duration)
                end
                ratelimited_ips[k] = nil
        end
        v.queries = 0
  end
end

-- match uncommon qtype like NULL (10), PRIVATE (65399) - works fine to block iodine
addAction(AndRule({OrRule({QTypeRule(10), QTypeRule(65399)}), NotRule(SuffixMatchNodeRule(trusted_domains, true)) }), SetTagAction('malicious_qtypes', 'matched'))

-- match long qname - 2 labels with a minimum of 50 bytes each - works fine to block tools like iodine, dnscat2, dns2tcp...
-- to avoid false-positive. The regex has been tested on the top 1 million list exposed by Cisco Umbrella http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip
addAction(AndRule({RegexRule('([^.]{50,}\\.){2,}'), NotRule(SuffixMatchNodeRule(trusted_domains, true)) }), SetTagAction('malicious_longqnames', 'matched'))

-- rate limiting on TXT, CNAME and MX
addAction(AndRule({ MaxQPSIPRule(5, 32, 64, 5), OrRule({QTypeRule(DNSQType.TXT), QTypeRule(DNSQType.CNAME), QTypeRule(DNSQType.MX)}), NotRule(SuffixMatchNodeRule(trusted_domains, true)) }), SetTagAction('malicious_ratelimiting', 'matched'))

-- logging malicious queries on remote dnstap logger
addAction(TagRule('malicious_qtypes'), DnstapLogAction("event_deniedqtypes_detected", security_dnstap_logger))
addAction(TagRule('malicious_longqnames'), DnstapLogAction("event_longqnames_detected", security_dnstap_logger))
addAction(TagRule('malicious_ratelimiting'), DnstapLogAction("event_ratelimiting_detected", security_dnstap_logger))

-- finally refuses and blacklist client ip during limited time
addAction(TagRule('malicious_qtypes'), LuaAction(blacklistIP))
addAction(TagRule('malicious_longqnames'), LuaAction(blacklistIP))
addAction(TagRule('malicious_ratelimiting'), LuaAction(countRateLimit))

-- Update the dynamic blocks with refused reply by default
setDynBlocksAction(DNSAction.Refused)

-- Rate exceeded detection with automatic ip blacklisting during 60s
--  * max bw to 1000bytes/s during 5s
local dbr = dynBlockRulesGroup()
dbr:setResponseByteRate(1000, 5, "Exceeded resp BW rate", 60)

-- check dynamic rule every second
function maintenance()
  dbr:apply()
end

-- default rule
addAction( AllRule(), PoolAction("default"))