DNS Cache Snoop
===============

* Author: Felipe Molina (@felmoltor)
* Date: February 2014
* Summary: Time Based DNS Cache Snooping Tool
* Dev. Status. BETA

Intro
-----

This script tries to add some features missing on other DNS snooping scripts like nmap script dns-cache-snoop or dns-snoopy. 

I never could obtain any valid results from __dns-cache-snoop script__ (http://nmap.org/nsedoc/scripts/dns-cache-snoop.html). Also, you have to set the domain names in the same command line when executing nmap, being a bit awkward to test for hundreds of domains.

With __dns-snoopy__ (https://github.com/z0mbiehunt3r/dns-snoopy), even being a very good tool I couldn't find a way to execute those queries to DNS servers of my election.

None of those tools also provided the user a fast way to test more than one DNS server at once, so DNSCacheSnoop was programmed to allow us provide multiple DNS servers and multiple domains to test.

DNSCacheSnoop is based on __response time__ of the targeted DNS to conclude if a domain is cached or not. 
This decision (domain cached or not) is dynamicaly adjusted by the script observing baseline time responses for cached domains, requesting the target DNS server a valid domain two times. The second time the domain is requested to this DNS, the entry will be already in its cache and the response time of the DNS server will be smaller than the first one.

Usage
-----

```
Usage: dnscachesnoop [options]
    -D, --dns-file FILE              File with the list of DNS servers to test
    -d, --dns SERVER                 Single server IP or name of the DNS to test
    -Q, --queries-file FILE          File with the list of domain names to snoop on the target DNS servers
    -q, --query DOMAIN               Single domain name to test on targets DNS servers
    -o, --out [FILE]                 File name where to save the results in csv format
    -t, --threshold [TIME]           Force a time threshold to consider a domain is cached in the DNS server (Default is computed dynamicaly)
        --[no-]warn-me               Don't show me the warning, I already know everything about DNS Snooping
    -h, --help                       Display this help screen
```

Required gems
-------------

* colorize (0.6.0)
* net-dns (0.8.0)

Warning
-------

With the execution of this tool (or any other kind of dns cache snooping) you are interacting with the target DNS server and sending it queries, so the target served will store in its cache the information of the resolved domains you asked for.

In subsequents executions of this script, you will probably receive __"false positives"__ telling you that all the domains you have requested are cached (recently visited by users of this DNS), but in fact, the last one who requested this domain information was YOU executing this script.

So you will have only one chance to get the real result from a DNS server, __the first one__. Be sure to have the correct list of domains before launthing this snoop attack.
