-- bind on ip any
setLocal('0.0.0.0:53', { reusePort=true })

-- allow all IP access
setACL("0.0.0.0/0")

-- admin interface control
controlSocket('0.0.0.0:5199')
setKey("pVC5gO/HECwOfgFzQDjAy6v5mWYmpwcj2h546GjqDgg=")

-- start the web server on port 8080
webserver("0.0.0.0:8080")
setWebserverConfig({
    acl="0.0.0.0/0", 
    password="hello", 
    apiKey="world",
    hashPlaintextCredentials=true, 
    apiRequiresAuthentication=false}
)

-- disable security feature polling
setSecurityPollSuffix('')

-- pool of backend dns
newServer({address="1.1.1.1:53", pool="default"})
newServer({address="9.9.9.9:53", pool="default"})
newServer({address="8.8.8.8:53", pool="default"})
newServer({address="8.8.4.4:53", pool="default"})
newServer({address="1.0.0.1:53", pool="default"})

-- default routing
addAction(AllRule(),PoolAction("default"))
