-- dnsdist configuration snippet

--- open your CDB database, example available here https://github.com/dmachard/blocklist-domains
--- dnsdist with reload this database every 3600s
kvs = newCDBKVStore("/etc/dnsdist/conf.d/blocklist.cdb", 3600)

-- block domains ?
addAction(KeyValueStoreLookupRule(kvs, KeyValueLookupKeyQName(false)), SetTagAction('policy_block'))
addAction(TagRule('policy_block', SpoofAction({"127.0.0.1", "::1"}))

--- or answer with NXDOMAIN
--- addAction(TagRule('policy_block'), RCodeAction(DNSRCode.NXDOMAIN))
