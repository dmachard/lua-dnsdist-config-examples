-- listen
setLocal("0.0.0.0:53", {})

-- backends
newServer({address = "8.8.8.8:53", pool="gcp"})
newServer({address = "1.1.1.1:53", pool="default"})

-- match traffic for googleapi
addAction(RegexRule(".*\\.googleapis\\.com"), PoolAction("gcp"))

-- default routing rule
addAction(AllRule(), PoolAction("default"))