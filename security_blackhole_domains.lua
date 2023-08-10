-- example to spoof some domains to localhost for A and AAAA queries

-- listen on localhost
setLocal("0.0.0.0:53", {})
-- backend dns
newServer({address = "1.1.1.1:53", pool="default"})

-- blackhole list from external files
blackhole_domains = newSuffixMatchNode()
for l in io.lines("/etc/dnsdist/blocklist.txt") do
  if l ~= "" then
    -- ignore commented lines
    if l:find("^#") == nil then
    	blackhole_list:add(newDNSName(l))
    end
  end
end

-- match blackhole domains and spoof response to localhost
addAction(SuffixMatchNodeRule(blackhole_domains, true), SpoofAction({"127.0.0.1", "[::1]"}, {ttl=3600}), {name="rule_blackholes"})

-- default rule
addAction( AllRule(), PoolAction("default"))