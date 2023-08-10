-- listen on localhost
setLocal("0.0.0.0:53", {})
-- backend dns
newServer({address = "1.1.1.1:53", pool="default"})
-- default rule
addAction( AllRule(), PoolAction("default"))