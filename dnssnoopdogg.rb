#!/usr/bin/env ruby

# Some interesting documentation about it:
#  * http://www.rootsecure.net/content/downloads/pdf/dns_cache_snooping.pdf
# This tools allows you to query a list of DNS servers for a list of domains and check if there is a recent visit of this domain in their cache.
# This method is the so called "DNS Cache Snooping". This snooping it's focused on response time.
# As there is some problems with dns-cache-snoop script of nmap and DNS Snoopy, I decided to write my own DNS Cache Snooping tool.

# TODO: Non polluting way: Use snooping technique with +norecurse (RD set to 0) in the query.
#       If the DNS server has the domain in its chache, it will answer you with the information needed, if not
#       it will answer you with an authority section.
# TODO: Polluting ways:
#           * Checking the TTL compared with the autoritative server of this domain. If it is a very low TTL compared with the autoritative DNS, it was cached some time ago by the target DNS.
#           * Checking the RTT of a packet to the server and compare with the time of the DNS query.

require 'colorize'
require 'net/dns'
require 'optparse'

#######

class DNSSnooper
    def initialize(server=nil,method="R",timetreshold=nil)
        @@baselineIterations = 4
        @@thresholdFactor = 0.25 # This factor is used to avoid falses positives produced by network issues
        @@ttlFactor = 0.7 # If the TTL of the targeted DNS is a X% smaller than the authoritative TTL, the domain was probably cached
        @method = method 
        @dnsserver = Net::DNS::Resolver.new(:nameservers => server,:udp_timeout=>15)
        @dnsserver.domain = "" # Avoid leaking local config of /etc/resolv.conf
        @dnsserver.searchlist = "" # Avoid leaking local config of /etc/resolv.conf
        if @method == "R"
            @dnsserver.recurse = false
        else
            @dnsserver.recurse = true
        end
        if !timetreshold.nil?
            @ctreshold = timetreshold
        end
    end

    private

    ##############
    
    def time
        start = Time.now
        yield
        Time.now - start
    end
    
    ##############

    def baselineRequestNonCached
        # Generate a random non existent domain and query it to the target DNS
        domain = (0...10).map { (65 + rand(26)).chr }.join.downcase
        domain += ".com"
        nctime = time do
            begin
                answer = @dnsserver.query(domain)
            rescue Exception => re
                puts "Error: #{re.message}"
            end
        end
        return nctime
    end
     
    ##############
   
    def baselineRequestCached(domain)
        # This function obtain the average time takes for a server to answer you with a cached entry.
        # It request twice the same existent domain to a server. The second time we request it, it answer
        # will be faster as it is already cached in the DNS.
        ctime = time do 
            begin
                @dnsserver.query(domain)
            rescue Exception => re
                puts "Error: #{re.message}"
            end
        end
        return ctime
    end

    ##############

    def getAuthoritativeTTL(domain)
        begin
            googledns = Net::DNS::Resolver.new(:nameservers => "8.8.8.8",:searchlist=>[],:domain=>[],:udp_timeout=>15)
            authDNSs = googledns.query(domain,Net::DNS::NS)
            authDNSs.answer.each{|dns|
                # Get the IP of this authdns and set it as our new DNS resolver
                # puts "DNS Class: #{dns.class}"
                if dns.class == Net::DNS::RR::NS
                    gresponse = googledns.query(dns.nsdname,Net::DNS::A)
                    if (!gresponse.answer[0].nil?)
                        dnsaddress = gresponse.answer[0].address.to_s
                        authdns = Net::DNS::Resolver.new(:nameservers => dnsaddress,:searchlist=>[],:domain=>[],:udp_timeout=>15)
                        authresponse = authdns.query(domain)
                        if authresponse.header.auth?
                            if !authresponse.answer[0].nil?
                                # This response is authoritative and we have a valid TTL
                                return authresponse.answer[0].ttl
                            elsif authresponse.authority.size > 0
                                # If we get a SOA redirection
                                # TODO:  Not sure how to handle this TTL from a SOA... Explore the protocol
                                if authresponse.authority[0].class == Net::DNS::RR::SOA
                                    soadns = authresponse.authority[0].mname
                                    # Get the IP of the SOA mname and set it as our new dns resolver
                                    soaip = googledns.query(soadns,Net::DNS::A).answer[0].address.to_s
                                    soa = Net::DNS::Resolver.new(:nameservers => soaip,:searchlist=>[],:domain=>[],:udp_timeout=>15)
                                    soaresponse = soa.query(domain,Net::DNS::A)
                                    if !soaresponse.answer[0].nil?
                                        return soaresponse.answer[0].ttl
                                    elsif !soaresponse.authority[0].nil?
                                        return soaresponse.authority[0].ttl
                                    else
                                        return nil
                                    end
                                end
                            else
                                return nil
                            end
                        end
                    else # If Google cannot find A records for this DNS server
                        if !gresponse.authority[0].nil?
                            if gresponse.authority[0].class == Net::DNS::RR::SOA
                                soadns = gresponse.authority[0].mname
                                # Get the IP of the SOA mname and set it as our new dns resolver
                                soaip = googledns.query(soadns,Net::DNS::A).answer[0].address.to_s
                                soa = Net::DNS::Resolver.new(:nameservers => soaip,:searchlist=>[],:domain=>[],:udp_timeout=>15)
                                soaresponse = soa.query(domain,Net::DNS::A)
                                if !soaresponse.answer[0].nil?
                                    return soaresponse.answer[0].ttl
                                elsif !soaresponse.authority[0].nil?
                                    return soaresponse.authority[0].ttl
                                else
                                    return nil
                                end
                            else
                                return nil
                            end
                        else
                            return nil
                        end
                    end
                else # This is not a DNS server but other type of record
                    if dns == Net::DNS::RR::SOA
                        soadns = dns.mname
                        # Get the IP of the SOA mname and set it as our new dns resolver
                        soaip = googledns.query(soadns,Net::DNS::A).answer[0].address.to_s
                        soa = Net::DNS::Resolver.new(:nameservers => soaip,:searchlist=>[],:domain=>[],:udp_timeout=>15)
                        soaresponse = soa.query(domain,Net::DNS::A)
                        if !soaresponse.answer[0].nil?
                            return soaresponse.answer[0].ttl
                        elsif !soaresponse.authority[0].nil?
                            return soaresponse.authority[0].ttl
                        else
                            return nil
                        end
                    else
                        return nil
                    end
                end
            }
        rescue Net::DNS::Resolver::NoResponseError => terror
            puts "Error: #{terror.message}"
            return nil
        end

        return nil
    end
     
    ##############
    
    public
    def obtainDNSThresholds
        # TODO: Change the testing domain if it is in the domain list the user provided
        maxcached = 0.0
        minnoncached = 9999.0
        d = "www.google.com"

        @@baselineIterations.times {
            noncachedth = baselineRequestNonCached
            cachedth = baselineRequestCached(d)
            if maxcached < cachedth
                maxcached = cachedth
            end
            if minnoncached > noncachedth
                minnoncached = noncachedth
            end
        }
        # Save the computed threshold times if there is not setted by the user
        if @cthreshold.nil?
            @cthreshold =  maxcached
        end
        return maxcached*1000,minnoncached*1000
    end
     
    ##############
    
    def isCached?(domain)
        timeToExpire = nil
        whenWasCached = nil
        isCached = nil
        
        # Obtain the authoritative TTL of the domain
        authTTL = getAuthoritativeTTL(domain)
        timeToExpire = authTTL
        
        case @method
        when "R"
            # Query with non-recurse bit
            begin
                dnsr = @dnsserver.query(domain)
            rescue Exception => e
                $stderr.puts "Error: #{e.message}"
            end
            # If the server has this entry cached, we will have an answer section
            # If the server does not have this entry cached, we will have an autoritative redirection
            if dnsr.answer.size > 0
                timeToExpire = dnsr.answer[0].ttl
                isCached = true
            else
                isCached = false
            end
        when "T"
            # If the TTL of the DNS is very low compared with the autoritative DNS TTL for this domain
            # It is very likely that this domain was cached some time ago.
            # If the TTL y equal or almost equal to the autoritative DNS TTL, it is probable that the
            # targeted DNS server just requested this information to the autoritative DNS
            if !authTTL.nil?
                dnsr = @dnsserver.query(domain)
                if (dnsr.answer[0].ttl.to_f < (@@ttlFactor * authTTL.to_f))
                    timeToExpire = dnsr.answer[0].ttl
                    isCached = true
                else 
                    isCached = false
                end
            end
        when "RT"
            # If the target DNS sever has the domain cached, the response time of it
            # should be faster than a query for a non cached domain and similar to 
            # a RTT of a ICMP packet
            answertime = time do
                begin
                    dnsr = @dnsserver.query(domain)
                rescue Exception => e
                    $stderr.puts "Error: #{e.message}"
                end
            end
            if answertime <= @cthreshold+(@cthreshold*@@thresholdFactor)
                timeToExpire = dnsr.answer[0].ttl
                isCached = true
            else
                isCached = false
            end
        end

        if !authTTL.nil? and !timeToExpire.nil?
            whenWasCached = authTTL - timeToExpire
        end
        
        return isCached,timeToExpire,whenWasCached
    end
end

##################
# UTIL FUNCTIONS #
##################

def parseOptions
  # This hash will hold all of the options
  # parsed from the command-line by
  # OptionParser.
  options = {:dnsfile => nil, :dnsserver=>nil, :domainsfile => nil, :domain=>nil, :output=>nil, :method =>"R", :warn => true}
  
  optparse = OptionParser.new do |opts|
    opts.on( '-D', '--dns-file FILE', 'File with the list of DNS servers to test') do |file|
      options[:dnsfile] = file
    end
    opts.on( '-d', '--dns SERVER', 'Single server IP or name of the DNS to test') do |server|
      options[:dnsserver] = server
    end
    opts.on( '-Q', '--queries-file FILE', 'File with the list of domain names to snoop on the target DNS servers') do |domains|
      options[:domainsfile] = domains
    end
    opts.on( '-q', '--query DOMAIN', 'Single domain name to test on targets DNS servers') do |domain|
      options[:domain] = domain
    end
    opts.on( '-m', '--method [METHOD]', 'Snoop method to use (R: Recursion based, T: TTL based, RT: Response Time based. Default is "R")') do |method|
      options[:method] = method
    end
    opts.on( '-o', '--out [FILE]', 'File name where to save the results in csv format') do |output|
      options[:output] = output
    end
    opts.on( '--[no-]warn-me', 'Don\'t show me the warning, I already know everything about DNS Snooping') do |warn|
      options[:warn] = warn
    end
    opts.on( '-h', '--help', 'Display this help screen' ) do
      print opts
      exit
    end
  end
  
  optparse.parse!(ARGV)
  
  if options[:dnsserver].nil? and options[:dnsfile].nil?
    $stderr.puts "Please, specify at least a DNS server (-d) or a list of DNS servers (-D)."
    puts optparse
    exit(1)
  end

  if options[:domainsfile].nil? and options[:domain].nil?
    $stderr.puts "Please, specify at least a domain (-q) or a list of domains (-Q) to query for."
    puts optparse
    exit(2)
  end
  options
end

###########

def saveResults(ofile,results)
    f = File.open(ofile,"w")

    header = ";#{results.keys.join(";")};"
    f.puts(header)
    # Iterate through explored domains
    results.values[0].keys.each{ |domain|
        line = "#{domain};"
        results.keys.each{|dns|
            line += "VISITED;" if results[dns][domain]
            line += "NOT VISITED;" if !results[dns][domain]
        }
        f.puts(line)
    }
    f.close
end

###########

def printBanner
    puts "####################################################".cyan
    puts "#        Author: Felipe Molina (@felmoltor)        #".cyan
    puts "#              Date: February 2014                 #".cyan
    puts "# Summary: Multiple method DNS Cache Snooping Tool #".cyan
    puts "#            Development Status: BETA              #".cyan
    puts "####################################################".cyan
    puts 
end

##########

def printWarning
    puts
    puts "**********************************************************************************************"
    puts "* Remember that executing this tool with methods 'T' or 'RT', you will query to the targeted *"
    puts "* DNS servers for domains.                                                                   *"
    puts "* The correctly resolved entries will be stored in the targeted DNS cache, so the subsequent *"
    puts "* executions of this script will produce false positives, telling you a domain is being      *"
    puts "* visited or requested by the users, when in fact the last person who requested the domain   *"
    puts "* was YOU executing this script.                                                             *"
    puts "*                                                                                            *"
    puts "* This wont happen with the method 'R', as the DNS server won't query other DNS servers if   *"
    puts "* the domain is not already cached, thus, avoiding the cache pollution of the targeted DNS.  *"
    puts "*                                                                                            *"
    puts "* In other words: You have ONLY ONE chance to get the real cache status of a DNS server (the *"
    puts "* first execution). Then you will have to WAIT some time to get real results from DNS servers*"
    puts "**********************************************************************************************"
    puts 
    print "Do you want to continue (y/N): "
    c = gets.chomp
    if c.upcase != "Y"
        exit(1) 
    end
end

#############

def toHumanTime(seconds)
    humantime = ""

    if seconds.to_i > 0
        mm, ss = seconds.divmod(60)
        hh, mm = mm.divmod(60) 
        dd, hh = hh.divmod(24) 

        ss = "0#{ss}" if (ss < 10)
        mm = "0#{mm}" if (mm < 10)
        hh = "0#{hh}" if (hh < 10)

        if dd.to_i > 0
            humantime += "#{dd} days, "
        end
        if hh.to_i > 0
            humantime += "#{hh}:"
        end
        humantime += "#{mm}:#{ss}"
    end
    return humantime
end

########
# MAIN #
########

printBanner
options = parseOptions
if options[:warn]
    printWarning
end

# Var
snoopresults = {}
dnsservers = []
domains = []

# Fill dns servers array
if options[:dnsfile].nil?
    dnsservers = [options[:dnsserver]]
elsif File.exists?(options[:dnsfile])
    File.open(options[:dnsfile],"r").each {|dns| dnsservers << dns.chop}
else
    $stderr.puts "Error. File #{options[:dnsfile]} does not exists."
    exit(3)
end
# Fill domains array
if options[:domainsfile].nil?
    domains = [options[:domain]]
elsif File.exists?(options[:domainsfile])
    File.open(options[:domainsfile],"r").each {|domain| domains << domain.chop}
else
    $stderr.puts "Error. File #{options[:domainsfile]} does not exists."
    exit(3)
end


dnsservers.each{ |dns|
    snoopresults[dns] = {}
    snooper = DNSSnooper.new(dns,options[:method],options[:timethreshold])
    puts
    puts "Recolecting response times from #{dns}"
    cachedth,noncachedth = snooper.obtainDNSThresholds
    print "Obtained cached thresholds for server "
    print "#{dns}".bold
    puts ":"
    print "- Max. response time for cached entries: "
    puts "#{cachedth.round(2)}ms".bold
    print "- Min. response time for non cached entries: "
    puts "#{noncachedth.round(2)}ms".bold
    if (cachedth >= noncachedth and options[:method] == "RT")
        puts "Those values are strange. They are inversed. Maybe the following results are not very reliable...".red
    end
    puts

    domains.each {|domain|
        print "* "
        print "#{domain}".bold
        isCached,timeToExpire,whenWasCached = snooper.isCached?(domain)

        if isCached.nil?
            puts " [UNKNOWN]".yellow
        else
            if isCached
                snoopresults[dns][domain] = true
                print " [VISITED]".green
                puts " (Cached #{toHumanTime(whenWasCached)} ago, Time To Expire #{toHumanTime(timeToExpire)})"
            else
                snoopresults[dns][domain] = false
                print " [NOT VISITED]".red
                puts " (In the last #{toHumanTime(timeToExpire)})"
            end
        end
    }
}

if !options[:output].nil?
    puts
    puts "Saving the results in #{options[:output]}..."
    saveResults(options[:output],snoopresults)
end

puts
puts "Snooping finished."
print "If you used techniques 'T' or 'RT', "
print "wait some time ".red
puts "until execute the snooping again to avoid the false positives produced by your own queries"
puts
