#!/usr/bin/env ruby

# This tools allows you to query a list of DNS servers for a list of domains and check if there is a recent visit of this domain in their cache.
# This method is the so called "DNS Cache Snooping". This snooping it's focused on response time.
# As there is some problems with dns-cache-snoop script of nmap and DNS Snoopy, I decided to write my own DNS Cache Snooping tool.

require 'colorize'
require 'resolv'
require 'optparse'

#######

class DNSSnooper
    def initialize(server=nil,timetreshold=nil)
        @@baselineIterations = 3
        @@thresholdFactor = 0.25 # This factor is used to avoid falses positives produced by network issues
        @dnsserver = Resolv::DNS.new(:nameserver=>server)
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
                @dnsserver.getaddress(domain)
            rescue Resolv::ResolvError => re
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
                @dnsserver.getaddress(domain)
            rescue Resolv::ResolvError => re
                puts "Error: #{re.message}"
            end
        end
        return ctime
    end
     
    ##############
    
    public
    def obtainDNSThresholds
        # TODO: Change the testing domain if it is in the domain list the user provided
        maxcached = 0.0
        avgnoncached = 0.0
        d = "www.google.com"

        @@baselineIterations.times {
            noncachedth = baselineRequestNonCached
            cachedth = baselineRequestCached(d)
            if maxcached < cachedth
                maxcached = cachedth
            end
            avgnoncached += noncachedth
        }
        # Save the computed threshold times if there is not setted by the user
        if @cthreshold.nil?
            @cthreshold =  maxcached
        end
        return maxcached*1000,(avgnoncached/@@baselineIterations)*1000
    end
     
    ##############
    
    def isCached?(domain)
        # Query with dns
        answertime = time do
            begin
                answer = @dnsserver.getaddress(domain)
            rescue Resolv::ResolvError => e

            end
        end
        # get the time of the response
        #puts "Comparando:"
        #puts "Answertime #{answertime}"
        #puts "Threshold: #{@cthreshold}"
        #puts "Confidence threshold: #{@cthreshold+(@cthreshold*@@thresholdFactor)}"
        if answertime <= @cthreshold+(@cthreshold*@@thresholdFactor)
            return true
        else
            return false
        end        
    end
end

##################
# UTIL FUNCTIONS #
##################

def parseOptions
  # This hash will hold all of the options
  # parsed from the command-line by
  # OptionParser.
  options = {:dnsfile => nil, :dnsserver=>nil, :domainsfile => nil, :domain=>nil, :output=>nil, :timetreshold => 15, :warn => true}
  
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
    opts.on( '-o', '--out [FILE]', 'File name where to save the results in csv format') do |output|
      options[:output] = output
    end
    opts.on( '-t', '--threshold [TIME]', 'Force a time threshold to consider a domain is cached in the DNS server (Default is computed dynamicaly)' ) do |threshold|
      options[:threshold] = threshold
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

def printWarning
    puts
    puts "**********************************************************************************************"
    puts "* Remember that executing this tool, you will query to the targeted DNS servers for domains  *"
    puts "* The correctly resolved entries will be stored in the targeted DNS cache, so the subsequent *"
    puts "* executions of this script will produce false positives, telling you a domain is being      *"
    puts "* visited or requested by the users, when in fact the last person who requested the domain   *"
    puts "* was YOU executing this script.                                                             *"
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
    snooper = DNSSnooper.new(dns,options[:timethreshold])
    puts
    puts "Recolecting response times from #{dns}"
    cachedth,noncachedth = snooper.obtainDNSThresholds
    print "Obtained cached thresholds for server "
    print "#{dns}".bold
    puts ":"
    print "- Max. response time for cached entries: "
    puts "#{cachedth.round(2)}ms".bold
    print "- Avg. response time for non cached entries: "
    puts "#{noncachedth.round(2)}ms".bold
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
