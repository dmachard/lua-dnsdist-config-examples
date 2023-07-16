-- example to spoof some domains to localhost for A and AAAA queries

-- blackhole list
blackhole_domains = newSuffixMatchNode()
blackhole_domains:add(newDNSName("baddomain.fr."))

-- match blackhole domains and spoof response to localhost
addAction(SuffixMatchNodeRule(blackhole_domains, true), SpoofAction({"127.0.0.1", "[::1]"}, {ttl=3600}), {name="rule_blackholes"})
