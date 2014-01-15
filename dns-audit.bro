# Written by Jon Schipp
# Detects when hosts send DNS requests to non-local DNS servers.
# 	To use:
# 		1. Add script to configuration local.bro: $ echo '@load dns-audit.bro' >> $BROPREFIX/share/bro/site/local.bro
# 		2. Copy script to $BROPREFIX/share/bro/site
# 		3. $ broctl check && broctl install && broctl restart

@load base/frameworks/notice

const dns_servers: set[addr] = {
	192.168.1.2,
	192.168.1.3,
} &redef;

const dns_ignore: set[addr] = {
	192.168.1.255,
	224.0.0.252,
	224.0.0.251,
} &redef;

const dns_port_ignore: set[port] = {
	5353/udp,
	137/udp,
} &redef;

export {

        redef enum Notice::Type += {
                DNS::Request_Sent_To_Wrong_Server
        };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
        {

	# Exit event handler if originator is not in networks.cfg
	if (! Site::is_local_addr(c$id$orig_h) )
		return;

	# Exit event handler if originator is an ignore address
	if ( c$id$orig_h in dns_ignore )
		return;

	# Exit event handler if originator is our local dns server
	if ( c$id$orig_h in dns_servers )
		return;

	# Exit event handler if port is a ignored DNS port
	if ( c$id$resp_p in dns_port_ignore )
		return;

        if ( c$id$resp_h !in dns_servers )
                {
                NOTICE([$note=DNS::Request_Sent_To_Wrong_Server,
                $msg="DNS Request destined to non-local DNS servers", $conn=c,
                $identifier=cat(c$id$orig_h,c$id$resp_h),
                $suppress_for=1day]);
                }
        }
