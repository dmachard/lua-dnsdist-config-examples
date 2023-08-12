-- listen
setLocal("0.0.0.0:53", {})

-- backends
newServer({address = "8.8.8.8:53", pool="google"})
newServer({address = "1.1.1.1:53", pool="default"})

-- tag DNS queries for google.com
addAction("google.com", SetTagAction('google-tag", "matched"))

-- route all google.com dns resolution to the specific pool of server
addAction(TagRule('google-tag', 'matched'), PoolAction("google"))

-- default rule
addAction( AllRule(), PoolAction("default"))