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
        @@baselineIterations = 3
        @@thresholdFactor = 0.25 # This factor is used to avoid falses positives produced by network issues
        @@ttlFactor = 0.7 # If the TTL of the targeted DNS is a X% smaller than the authoritative TTL, the domain was probably cached
        @method = method 
        @dnsserver = Net::DNS::Resolver.new(:nameservers => server)
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
        googledns = Net::DNS::Resolver.new(:nameservers => "8.8.8.8",:searchlist=>[],:domain=>[])
        authDNSs = googledns.query(domain,Net::DNS::NS)
        authDNSs.answer.each{|dns|
            # Get the IP of this authdns and set it as our new DNS resolver
            dnsaddress = googledns.query(dns.nsdname,Net::DNS::A).answer[0].address.to_s
            authdns = Net::DNS::Resolver.new(:nameservers => dnsaddress,:searchlist=>[],:domain=>[])
            authresponse = authdns.query(domain)
            if authresponse.header.auth?
                # This response is authoritative and we have a valid TTL
                return authresponse.answer[0].ttl
            end
        }
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
        whenWasCached = 0
        isCached = false
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
                whenWasCached = dnsr.answer[0].ttl
                isCached = true
            end
        when "T"
            # If the TTL of the DNS is very low compared with the autoritative DNS TTL for this domain
            # It is very likely that this domain was cached some time ago.
            # If the TTL y equal or almost equal to the autoritative DNS TTL, it is probable that the
            # targeted DNS server just requested this information to the autoritative DNS
            authTTL = getAuthoritativeTTL(domain)
            if !authTTL.nil?
                puts "The authoritative TTL of this domain is #{authTTL}"
                dnsr = @dnsserver.query(domain)
                puts "The TTL of targeted DNS is #{dnsr.answer[0].ttl}"
                if (dnsr.answer[0].ttl.to_f < (@@ttlFactor * authTTL.to_f))
                    whenWasCached = dnsr.answer[0].ttl
                    isCached = true
                end
            end
        when "RT"
            # Query with dns
            answertime = time do
                begin
                    dnsr = @dnsserver.query(domain)
                rescue Exception => e
                    $stderr.puts "Error: #{e.message}"
                end
            end
            if answertime <= @cthreshold+(@cthreshold*@@thresholdFactor)
                whenWasCached = dnsr.answer[0].ttl
                isCached = true
            end
        end

        return isCached
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
    if options[:method] == "R"
        snooper = DNSSnooper.new(dns,false,options[:timethreshold])
    else
        snooper = DNSSnooper.new(dns,true,options[:timethreshold])
    end
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
    if (cachedth >= noncachedth)
        puts "Those values are strange. They are inversed. Maybe the following results are not very reliable...".red
    end
    puts

    domains.each {|domain|
        print "* "
        print "#{domain}".bold
        if snooper.isCached?(domain)
            snoopresults[dns][domain] = true
            puts " [VISITED]".green
        else
            snoopresults[dns][domain] = false
            puts " [NOT VISITED]".red
        end
    }
}

if !options[:output].nil?
    puts
    puts "Saving the results in #{options[:output]}..."
    saveResults(options[:output],snoopresults)
end

puts "Snooping finished."
puts "Please, wait some time until execute the snooping again to avoid the false positives produced by your own queries".red
puts
