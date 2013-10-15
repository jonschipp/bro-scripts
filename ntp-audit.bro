# Written by Jon Schipp, 01-10-2013
#
# Detects when hosts send NTP messages to NTP servers not defined in time_servers.
#       To use:
#               1. Enable the NTP analyzer:
#
#               If running Bro 2.1 add lines to local.bro:
#
#                       global ports = set(123/udp);
#                       redef dpd_config += { [ANALYZER_NTP] = [$ports = ports]
#                       };
#                  
#               If running Bro 2.2 add lines to local.bro:
#
#                       event bro_init()
#                       {
#                              local ports = set(123/udp);
#                              Analyzer::register_for_ports(Analyzer::ANALYZER_NTP,
#                              ports);
#                       }
#
#               2. Copy ntp-audit.bro script to $BROPREFIX/share/bro/site
#               3. Place the following line into local.bro and put above code from step 1:
#                       @load ntp-audit.bro
#               4. Run commands to validate the script, install it, and put into production: 
#                       $ broctl check && broctl install && broctl restart
#
#       If you would like to receive e-mails when a notice event is generated add to emailed_types in local.bro:
#               e.g.
#                       redef Notice::emailed_types += {
#                               MyScripts::Query_Sent_To_Wrong_Server,
#                       };


@load base/frameworks/notice

# Use namespace so variables don't conflict with those in other scripts
module MyScripts;

# Export sets and types so that they can be redefined outside of this script
export {

        redef enum Notice::Type += {
                Query_Sent_To_Wrong_Server
        };

        # List your NTP servers here    
        const time_servers: set[addr] = {
        192.168.1.250,
        192.168.1.251,
        } &redef;

        # List any source addresses that should be excluded
        const time_exclude: set[addr] = {
        192.168.1.250,
        192.168.1.251,
        192.168.1.1, # Gateway/NAT/WAN uses external source for time
        } &redef;

}

event ntp_message(u: connection, msg: ntp_msg, excess: string)
        {

	 # Exit event handler if originator is not in networks.cfg
	if (! Site::is_local_addr(u$id$orig_h) )
		return;

        if ( u$id$orig_h !in time_exclude && u$id$resp_h !in time_servers )
                {
                NOTICE([$note=Query_Sent_To_Wrong_Server,
                $msg="NTP query destined to non-defined NTP servers", $conn=u,
                $identifier=cat(u$id$orig_h),
                $suppress_for=1day]);
                }
        }
~          
