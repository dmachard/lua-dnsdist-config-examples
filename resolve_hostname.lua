-- dnsdist configuration snippet

-- listen on localhost
setLocal("0.0.0.0:53", {})
-- backend dns
newServer({address = "1.1.1.1:53", pool="default"})

-- resolve hostname
local f = assert(io.popen('getent hosts <YOURDNSNAME> | cut -d " " -f 1', 'r'))
local dnscollector = f:read('*a') or "127.0.0.1"
f:close()
dnscollector = string.gsub(dnscollector, "\n$", "")

-- get hostname
local f = io.popen ("/bin/hostname")
local hostname = f:read("*a") or "dnsdist"
f:close()
hostname = string.gsub(hostname, "\n$", "")

-- use in action
fstl = newFrameStreamTcpLogger(dnscollector.. ":6000")
addAction(AllRule(), DnstapLogAction(hostname, fstl))

-- default rule
addAction( AllRule(), PoolAction("default"))

