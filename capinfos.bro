# Written by Jon Schipp
# 	To use:
#		$ bro -b -r capture.pcap conn-count.bro

global connections_seen_counter = 0;
global orig_seen_s: set[addr];
global resp_seen_s: set[addr];
global time_first: time;
global time_last: time;

event bro_init()
	{
	print fmt("Bro Version: %s", bro_version());
	}

event new_connection(c: connection)
        {
	
	if ( connections_seen_counter == 0 )
		time_first = network_time();
	
	time_last = network_time();
	++connections_seen_counter;
	add orig_seen_s[c$id$orig_h];
	add resp_seen_s[c$id$resp_h];
        }

event bro_done()
	{
	print fmt("Start: %DT", time_first);
	print fmt("End: %DT", time_last);
	print fmt(" -- Connections Seen: --");
	print fmt("Connections: %d", connections_seen_counter);
	print fmt("Unique Originators: %d", |orig_seen_s|);
	print fmt("Unique Responders: %d", |resp_seen_s|);
	print fmt("Total Unique Hosts: %d", |orig_seen_s| + |resp_seen_s|);
	}
