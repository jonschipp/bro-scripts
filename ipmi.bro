# Written by Jon Schipp
# Rudimentary detection of IPMI traffic by matching destination port 623/udp
# 	To use:
# 		1. Add script to configuration local.bro: $ echo '@load ipmi.bro' >> $BROPREFIX/share/bro/site/local.bro
# 		2. Copy script to $BROPREFIX/share/bro/site
# 		3. $ broctl check && broctl install && broctl restart

@load base/frameworks/notice

export {
        redef enum Notice::Type += {
                IPMI::Port_Detected
        };
}

redef Notice::emailed_types += {
        IPMI::Port_Detected
};

event new_connection(c: connection)
        {
        if ( ! Site::is_local_addr(c$id$orig_h) && Site::is_local_addr(c$id$resp_h) && c$id$resp_p == 623/udp)
                {
                NOTICE([$note=IPMI::Port_Detected, $msg=fmt("Host %s sent traffic to UDP port %d.", c$id$orig_h, c$id$resp_p),
		$conn=c, $identifier=cat(c$id$orig_h,c$id$resp_p), $suppress_for=1day]);
                }
        }

