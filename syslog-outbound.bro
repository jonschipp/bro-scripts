# Generates a notice and e-mail if syslog messages are destined to non-local networks
# i.e. networks not defined in networks.cfg.
# 	To use:
# 		1. Add script to configuration local.bro: $ echo '@load syslog-outbound.bro' >> $BROPREFIX/share/bro/site/local.bro
# 		2. Copy script to $BROPREFIX/share/bro/site
# 		3. broctl check && broctl install && broctl restart

@load base/frameworks/notice

export {
        redef enum Notice::Type += {
                SYSLOG::Detected_Outbound_Message
        };
}

redef Notice::emailed_types += {
                SYSLOG::Detected_Outbound_Message
};

event syslog_message(c: connection, facility: count, severity: count, msg: string)
        {
        if ( Site::is_local_addr(c$id$orig_h) && ! Site::is_local_addr(c$id$resp_h) )
                {
                NOTICE([$note=SYSLOG::Detected_Outbound_Message,
                $msg="Syslog message destined to non-local networks", $conn=c,
                $identifier=cat(c$id$orig_h,c$id$resp_h),
                $suppress_for=1day]);
                }
        }
