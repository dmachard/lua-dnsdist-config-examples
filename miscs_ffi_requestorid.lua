-- listen on localhost
setLocal("0.0.0.0:53", {})

-- init backend
newServer({address = "1.1.1.1:53", pool="default"})

-- init remote logger 
pl = newRemoteLogger("192.168.1.6:6000")

local ffi = require("ffi")
function luaffiactionsetrequestorid(dq)
   local currentRequestor= "forbar"
   ffi.C.dnsdist_ffi_dnsquestion_set_requestor_id(dq, currentRequestor, #currentRequestor)
   return DNSAction.None
end

-- rules for queries
addAction(AllRule(), LuaFFIAction(luaffiactionsetrequestorid))
addAction(AllRule(), RemoteLogAction(pl, nil, {serverID="dnsdist"}))
addAction( AllRule(), PoolAction("default"))

-- rules for replies
addResponseAction(AllRule(), RemoteLogResponseAction(pl, nil, true, {serverID="dnsdist"}))
addCacheHitResponseAction(AllRule(), RemoteLogResponseAction(pl, nil, true, {serverID="dnsdist"}))
