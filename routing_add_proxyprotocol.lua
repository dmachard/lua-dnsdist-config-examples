
-- dnsdist edge

-- enable proxy protocol
newServer({ 
	useProxyProtocol=true,
})

-- add more value, ex: local ip of the dnsdist
function addProxyProtocolValues(dq)
  dq:addProxyProtocolValue(1, dq.localaddr:tostring() )
  return DNSAction.None
end

-- add proxy value on all queries
addAction(AllRule(),LuaAction(addProxyProtocolValues))


--------------------------
---------------------------

-- dnsdist side

-- list netmask or ip to 
setLocal('0.0.0.0:53', { reusePort=true, enableProxyProtocol=true })
setProxyProtocolACL({'192.168.1.17/32'})

nmg = newNMG()
nmg:addMask("192.168.1.251/32")

addAction(AndRule({NetmaskGroupRule(nmg,true,true),ProxyProtocolValueRule(1, "192.168.1.17")}), PoolAction("google"))
addAction(AllRule(), RCodeAction(DNSRCode.REFUSED))

