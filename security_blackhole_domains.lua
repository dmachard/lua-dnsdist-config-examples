-- example to spoof some domains to localhost for A and AAAA queries

-- blackhole list from external files
-- example of content
-- cat /etc/dnsdist/blackhost_list.txt
-- baddomain.fr.
blackhole_domains = newSuffixMatchNode()
for l in io.lines("/etc/dnsdist/blackhost_list.txt") do blackhole_domains:add(newDNSName(l)) end

-- match blackhole domains and spoof response to localhost
addAction(SuffixMatchNodeRule(blackhole_domains, true), SpoofAction({"127.0.0.1", "[::1]"}, {ttl=3600}), {name="rule_blackholes"})
