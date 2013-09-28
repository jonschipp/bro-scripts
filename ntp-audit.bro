# Written by Jon Schipp
# Detects when hosts send NTP queries to NTP servers not defined in time_servers.
# 	To use:
# 		1. Add script to configuration local.bro: $ echo '@load ntp-audit.bro' >> $BROPREFIX/share/bro/site/local.bro
# 		2. Copy script to $BROPREFIX/share/bro/site
# 		3. $ broctl check && broctl install && broctl restart

@load base/frameworks/notice

# List your NTP servers here	
const time_servers: set[addr] = {
	192.168.1.250,
	192.168.1.251,
} &redef;

# List any source addresses that should be excluded
const time_exclude: set[addr] = {
	192.168.1.250,
	192.168.1.251,
	192.168.1.1, # Gateway/NAT 
} &redef;

export {

        redef enum Notice::Type += {
                NTP::Query_Sent_To_Wrong_Server
        };
}

redef Notice::emailed_types += {
                NTP::Query_Sent_To_Wrong_Server
};

event udp_request(u: connection)
        {
        if ( u$id$orig_h !in time_exclude && u$id$resp_h !in time_servers && u$id$resp_p == 123/udp )
                {
                NOTICE([$note=NTP::Query_Sent_To_Wrong_Server,
                $msg="NTP query destined to non-defined NTP servers", $conn=u,
                $identifier=cat(u$id$orig_h),
                $suppress_for=1day]);
                }
        }
