-- Generic rules to block malicious dns traffic with regex

-- remote dnstap logger
security_dnstap_logger = newFrameStreamTcpLogger("10.0.0.100:6000")

-- white list to ignore some trusted domains
malicious_white_list = newSuffixMatchNode()
malicious_white_list:add(newDNSName("google.fr"))

-- match uncommon qtype like NULL (10), PRIVATE (65399) - works fine to block iodine
addAction(AndRule({OrRule({QTypeRule(10), QTypeRule(65399)}), NotRule(SuffixMatchNodeRule(malicious_white_list, true)) }), SetTagAction('block_malicious', ''))

-- match long qname - 2 labels with a minimum of 50 bytes each - works fine to block tools like iodine, dnscat2, dns2tcp...
-- to avoid false-positive. The regex has been tested on the top 1 million list exposed by Cisco Umbrella http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip
addAction(AndRule({RegexRule('([^.]{50,}\\.){2,}'), NotRule(SuffixMatchNodeRule(malicious_white_list, true)) }), SetTagAction('block_malicious', ''))

-- logging malicious queries on remote dnstap logger
addAction(TagRule('block_malicious'), DnstapLogAction("malicious_blocked", security_dnstap_logger))

-- finally refused malicious queries
addAction(TagRule('block_malicious'), RCodeAction(DNSRCode.REFUSED))

-- Update the dynamic blocks with refused reply by default
setDynBlocksAction(DNSAction.Refused)

-- Rate exceeded detection with automatic ip blacklisting during 60s
--  * max 5req/s during 5s for TXT, CNAME and MX
--  * max bw to 1000bytes/s during 5s
local dbr = dynBlockRulesGroup()
dbr:setQTypeRate(DNSQType.TXT, 5, 5, "Exceeded TXT rate", 60)
dbr:setQTypeRate(DNSQType.CNAME, 5, 5, "Exceeded CNAME rate", 60)
dbr:setQTypeRate(DNSQType.MX, 5, 5, "Exceeded MX rate", 60)
dbr:setResponseByteRate(1000, 5, "Exceeded resp BW rate", 60)

-- check dynamic rule every second
function maintenance()
  dbr:apply()
end
