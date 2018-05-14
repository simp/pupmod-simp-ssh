#
# Query and report SSHD ciphers under different conditions
#
# This can be used to help validate the claims in the README.md
#
# report files are written to the (valid) path in env var $SIMP_SSH_report_dir
#
#   server: SUT to query
#   label:  descriptive filename segment
#   text:   Any custom text to add to the report
#
def dump_sshd_ciphers(server, label='', text='')
  facts_to_query = [
    'fips_enabled',
    'os.selinux.config_mode',
    'os.name',
    'os.release.major',
    'openssh_version',
    'ipa',
  ]

  # gather
  _sshd_T = on(server, 'sshd -T | grep "^\(ciphers\|macs\|kexalgorithms\) "')
  unless _sshd_T.exit_code == 0
    warn( 'WARNING: sshd -T failed during dump_sshd_ciphers')
    return false
  end

  _f = on(server, facter(%w(-y -p) + facts_to_query))
  unless _f.exit_code == 0
    warn( 'WARNING: facter failed during dump_sshd_ciphers')
    return false
  end

  # compile
  sshd_info = Hash[Hash[_sshd_T.stdout.split(/\n/).map{|x| x.split(' ')}].map{|k,v| [k, v.split(',')]}]
  facts = Hash[Hash[_f.stdout.split(/\n/).map{|x| x.split(': ')}].map{|k,v| [k,v.gsub(/"/,'')]}]
  id_string = "#{facts['os.name']}-#{facts['os.release.major']}" \
              "__fips-#{facts['fips_enabled']}" \
              "__ssh-#{facts['openssh_version']}" \
              "__sel-#{facts['os.selinux.config_mode']}".downcase
  id_string += "__ipa-#{facts['ipa']}" unless facts['ipa'].empty?
  id_string += "__#{label}" unless label.empty?

  # build report
  lines = []
  lines << 'Environment:'
  lines << "- #{facts['os.name']} #{facts['os.release.major']}"
  lines << "- openssh_version: #{facts['openssh_version']}"
  lines << "- fips_enabled: #{facts['fips_enabled']}"
  lines << "- selinux_mode: #{facts['os.selinux.config_mode']}"
  lines << "- ipa: #{facts['ipa'].empty? ? '' : facts['ipa']}"
  lines << "\n"
  lines << 'Ciphers:'
  lines << sshd_info['ciphers'].map{|x| "- `#{x}`"}
  lines << "\n"
  lines << 'MACs:'
  lines << sshd_info['macs'].map{|x| "- `#{x}`"}
  lines << "\n"
  lines << 'kexalgorithms:'
  lines << sshd_info['kexalgorithms'].map{|x| "- `#{x}`"}
  unless text.empty?
    lines << "\n"
    lines << text
  end
  report = lines.join("\n")

  # report
  warn '', report, ''
  _dir = ENV.fetch('SIMP_SSH_report_dir','')
  if File.directory?(_dir)
    _file = File.join(_dir,"#{id_string}.md")
    File.write(_file, report)
    warn("dumped sshd -T summary to '#{_file}'")
  end
end
