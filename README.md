DNS Cache Snoop
===============

* Author: Felipe Molina (@felmoltor)
* Date: February 2014
* Summary: Time Based DNS Cache Snooping Tool
* Dev. Status. BETA
* Video Demonstration: https://www.youtube.com/watch?v=6VVZJV3wbi8

Intro
-----

This script tries to add some features missing on other DNS snooping scripts like nmap script dns-cache-snoop or dns-snoopy. 

I never could obtain any valid results from __dns-cache-snoop script__ (http://nmap.org/nsedoc/scripts/dns-cache-snoop.html). Also, you have to set the domain names in the same command line when executing nmap, being a bit awkward to test for hundreds of domains.

With __dns-snoopy__ (https://github.com/z0mbiehunt3r/dns-snoopy), even being a very good tool I couldn't find a way to execute those queries to DNS servers of my election.

None of those tools also provided the user a fast way to test more than one DNS server at once, so DNSCacheSnoop was programmed to allow us provide multiple DNS servers and multiple domains to test.

This tool provides you tree (3) methods to snoop the DNS cache:
* Non Polluting way: 
    1. (R): Using the RD (_Recursion Desired_) bit set to 0. In this case the DNS server will answer you with a response if it is already cached, but wont give you any answer if is not, as you requested it to avoid recursion (not letting it to query another DNS servers for the answer). This method __won't pollute__ the targeted DNS cache.
* Polluting way:
    2. (T) Using TTL: Observing the TTL of the entries requested to the DNS server and comparing them to the authoritative TTL provided by the authoritative(s) DNS servers for this domain. If the TTL smaller (let say a 70% smaller) we can conclude that this server had this entry cached before we asked for it.
    3. (RT) Using Response Time: (Still in development and bug fixing) Observing and comparing the time it takes the targeted DNS to answer us for a cached entry and a non cached entry. We request to the server two times (or more) the same baseline domain (for example google.es) to get the average time the DNS server needs to answer us for a cached domain. We store the maximum time of the test(s). Then, the tool will conclude that an entry was not cached if the time of the answer is greater than this value or conclude it was cached if the time is smaller. __This method is the less effective__ for now and we will find a lot DNS servers answering us with similar response times for cached and non-cached entries.

Usage
-----

```
age: dnscachesnoop [options]
    -D, --dns-file FILE              File with the list of DNS servers to test
    -d, --dns SERVER                 Single server IP or name of the DNS to test
    -Q, --queries-file FILE          File with the list of domain names to snoop on the target DNS servers
    -q, --query DOMAIN               Single domain name to test on targets DNS servers
    -m, --method [METHOD]            Snoop method to use (R: Recursion based, T: TTL based, RT: Response Time based. Default is "R")
    -o, --out [FILE]                 File name where to save the results in csv format
    --[no-]warn-me               Don't show me the warning, I already know everything about DNS Snooping
    -h, --help                       Display this help screen
                                    
```

Required gems
-------------

* colorize (0.6.0)
* net-dns (0.8.0)

Warning
-------

Remember that executing this tool with methods 'T' or 'RT', you will query to the targeted DNS servers for domains. 

The correctly resolved entries will be stored in the targeted DNS cache, so the subsequent executions of this script will produce false positives, telling you a domain is being visited or requested by the users, when in fact the last person who requested the domain was YOU executing this script.                                                             
In other words: You have ONLY ONE chance to get the real cache status of a DNS server (the first execution). Then you will have to WAIT some time to get real results from DNS servers.

This wont happen with the method 'R', as the DNS server won't query other DNS servers if the domain is not already cached, thus, avoiding the cache pollution of the targeted DNS.

