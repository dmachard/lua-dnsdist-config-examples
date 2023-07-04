-- dnsdist configuration

---------------------------------------------------
-- Dns services
---------------------------------------------------

-- udp/tcp dns listening
setLocal("0.0.0.0:53", {})

-- dns caching
pc = newPacketCache(10000, {})

---------------------------------------------------
-- Pools
---------------------------------------------------

pool_resolv = "resolvers"

-- members definition
newServer({
  name = "google",
  address = "8.8.8.8:53",
  pool = pool_resolv,
})

newServer({
  name = "quad9",
  address = "9.9.9.9:53",
  pool = pool_resolv,
})

-- set the load balacing policy to use
setPoolServerPolicy(roundrobin, pool_resolv)

-- enable cache for the pool
getPool(pool_resolv):setCache(pc)

---------------------------------------------------
-- Rules
---------------------------------------------------

-- matches all incoming traffic and send-it to the pool of resolvers
addAction(
  AllRule(),
  PoolAction(pool_resolv)
)
