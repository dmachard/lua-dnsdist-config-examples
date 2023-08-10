# Configurations for DNSdist

Configuration examples for DNSdist PowerDNS

Basic examples:

- [Configuration with load balancing on public DNS](./basic_config.lua)

Security configuration:

- [Security: Ads/Malwares blocking with external CDB database](./blacklist_cdb.lua)
- [Security: DNS tunneling blocking](./security_blocking_dnstunneling.lua)
- [Security: blackhole/spoofing domains with external files](./security_blackhole_domains.lua)
- [Security: Blacklist IP during XX seconds with DNS NOTIFY](./blacklist_ip_notify.lua)

Logging DNS traffic:

- [Logging DNS traffic with DNSTAP protocol](./logging_dnstap.lua)
- [Logging DNS traffic with Protobuf protocol](./logging_protobuf.lua)

Miscs:

- [Flush cache for domain with DNS NOTIFY](./cache_flush_notify.lua)
- [Echo capability of ip address from domain name for development](./echoip.lua)

## Run config from docker

Start

```bash
sudo docker run -d -p 5553:53/udp -p 5553:53/tcp --name=dnsdist --volume=$PWD/basic_config.lua:/etc/dnsdist/conf.d/dnsdist.conf:ro powerdns/dnsdist-18:1.8.0
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

Testing

```bash
dig @127.0.0.1 -p 5553 +tcp google.com
```
