Given some "real world" destination, I want to turn this into a BOSSWAVE URI.

to connect to a site, I publish to its URI.
to recv data from a site, it publishes to MY URI.
My URI is for all of my incoming connections.
The sites uri is for all of its incoming connections.

When i get an IP, do an rDNS lookup to get the DNS record. The DNS record can have TXT
record attached to it which is the URI that you publish to.
Attach another special BW object when I connect that contains my URI, so that the server
doesn't ahve to do a rdns lookup to reply back to me.

TODO:
- make sure i am juggling the src/dst topics correctly. How do I send *BACK* to somebody? 


Lets choose an IP range to use for the VPN. Gonna be IPv6!

fc00::/7
fc00:: – fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 
,h
fc00::0410:0:0:0:0
['0x42', '0x4f', '0x53', '0x53', '0x57', '0x41', '0x56', '0x45']

ASCII BOSSWAVE
fc00:424f:5353:5741:5645::/80

Test address: fc00:424f:5353:5741:5645::1
DNS TXT record: gabe.ns/ip/bw2ssltest
DNS AAAA record: bw2ssltest.cal-sdb.org

i type in bw2ssltest.cal-sdb.org
resolves to fc00:424f:5353:5741:5645::1, which is NOt globally routable
and this gets routed through my tun interface because i have a route there.
Then, the bw2ssl program does an rdns lookup to get the TXT record


//
- todo: check if the dns lookups actually work

new challenge: ok so i do the record lookup and i publish. I need to include
a way back. This is the "src" payload type. On the serverside, we create
a map of incoming src addr -> outoing dst topic. This way when we receive serverside
ip packets that are outgoing, it just looks up in a map for what to write!
