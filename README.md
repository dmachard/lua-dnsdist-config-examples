# Configurations for DNSdist

Configuration examples for DNSdist PowerDNS

**Admin configuration**:

- [DoH/DoT/Do53 listeners with all admin interfaces enabled](./advanced_config.lua)

**Routing DNS traffic**:

- [Match Qname with regular expression](./routing_regex.lua)
- [Tag your traffic and applied specified rules on it](./routing_tag_traffic.lua)

**Security configuration**:

- [Ads/Malwares blocking with external CDB database](./security_blacklist_cdb.lua)
- [DNS tunneling blocking](./security_blocking_dnstunneling.lua)
- [Blackhole/spoofing domains with external files](./security_blackhole_domains.lua)
- [Blacklist IP during XX seconds, the list of IPs is managed with DNS notify](./security_blacklist_ip_notify.lua)
- [Blacklist domains, the list is managed with DNS notify](./security_blacklist_ip_notify.lua)
- [Spoofing DNS responses like TXT, A, AAAA, MX and more...](./security_spoofing_qtype.lua)

**Logging DNS traffic**:

- [Remote DNS logging with DNSTAP protocol](./logging_dnstap.lua)
- [Remote DNS logging with Protobuf protocol](./logging_protobuf.lua)

**Miscs**:

- [Full configuration with load balancing on public DNS resolvers](./miscs_basic_config.lua)
- [Flush cache for domain with DNS NOTIFY](./miscs_cache_flush_notify.lua)
- [Echo capability of ip address from domain name for development](./miscs_echoip.lua)
- [Resolve hostname from config](./miscs_resolve_hostname.lua)

## Run config from docker

Start

```bash
sudo docker run -d -p 5553:53/udp -p 5553:53/tcp -p 8083:8080 --name=dnsdist --volume=$PWD/basic_config.lua:/etc/dnsdist/conf.d/dnsdist.conf:ro powerdns/dnsdist-18:1.8.0
```

Reload configuration

```bash
sudo docker stop dnsdist && sudo docker start dnsdist
```

Display logs

```bash
sudo docker logs dnsdist
dnsdist 1.8.0 comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it according to the terms of the GPL version 2
Added downstream server 1.1.1.1:53
Listening on 0.0.0.0:53
ACL allowing queries from: 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, ::1/128, fc00::/7, fe80::/10
Console ACL allowing connections from: 127.0.0.0/8, ::1/128
Marking downstream 1.1.1.1:53 as 'up'
Polled security status of version 1.8.0 at startup, no known issues reported: OK
```

Testing DNS resolution

```bash
dig @127.0.0.1 -p 5553 +tcp google.com
```

Testing Web console access

```bash
curl -u admin:open http://127.0.0.1:8083
```
