# Generates a notice and e-mail if syslog messages contain a PRI greater than 191 but less than 1016
#                                                                        fac: (23 but less than 127)
# Vulnerability: http://www.rsyslog.com/remote-syslog-pri-vulnerability/
#
#       To use:
#               1. Add script to configuration local.bro: $ echo '@load rsyslog-invalid-pri.bro' >> $BROPREFIX/share/bro/site/local.bro
#               2. Copy script to $BROPREFIX/share/bro/site
#               3. $ broctl check && broctl install && broctl restart
# Testing: 
# mausezahn -t syslog severity=7,facility=24,host=mausezahn -P "Invalid PRI message test" -B 141.142.148.91
# 
# Facility: Divide the PRI number by 8. 
# 191/8 = 23
# 
# Severity:  multiply facility by 8 and subtract from PRI
# 191 - (23 * 8 ) = 7
#   
#   PRI = Facility 23 and Priority (7)

# Possible combinations:
# for pri in {1..1016}; do FAC="$((pri/8))"; echo -e -n "PRI:$pri Fac:$FAC Sev:$((pri - ($FAC * 8 )))\n"; done

@load base/frameworks/notice

export {
        redef enum Notice::Type += {
                SYSLOG::Invalid_PRI
        };

        # List your NTP servers here    
        const syslog_servers: set[addr] = {
        141.142.148.91
        } &redef;

}

redef Notice::emailed_types += {
                SYSLOG::Invalid_PRI
};

event syslog_message(c: connection, facility: count, severity: count, msg: string)
        {

        if ( c$id$resp_h !in syslog_servers )
                return;

        if (facility > 23 && facility < 127)
                {
                NOTICE([$note=SYSLOG::Invalid_PRI,
                $msg=fmt("Syslog message with invalid PRI from %s to %s", c$id$orig_h, c$id$resp_h),
                $conn=c,
                $identifier=cat(c$id$orig_h,c$id$resp_h),
                $suppress_for=1day]);
                }
        }
