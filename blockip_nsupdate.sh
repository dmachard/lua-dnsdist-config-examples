#!/bin/sh

BLOCKIP=localhost
BLOCKPORT=5553
BLOCKHOST=blockip.local.dev

IPTTL=$2
IPADDR=$1

echo "server $BLOCKIP $BLOCKPORT" > /tmp/blockip_nsupdate.txt
echo "zone $BLOCKHOST" >> /tmp/blockip_nsupdate.txt
echo "update add $BLOCKHOST $IPTTL A $IPADDR" >> /tmp/blockip_nsupdate.txt
echo "send" >> /tmp/blockip_nsupdate.txt

nsupdate -d -v /tmp/blockip_nsupdate.txt