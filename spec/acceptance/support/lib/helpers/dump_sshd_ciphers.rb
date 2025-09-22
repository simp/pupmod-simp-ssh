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
def dump_sshd_ciphers(server, label = '', text = '')
  facts_to_query = [
    'fips_enabled',
    'os.selinux.config_mode',
    'os.name',
    'os.release.major',
    'openssh_version',
    'ipa',
  ]

  # gather
  sshd_t_output = on(server, 'sshd -T | grep "^\(ciphers\|macs\|kexalgorithms\) "')
  unless sshd_t_output.exit_code == 0
    warn('WARNING: sshd -T failed during dump_sshd_ciphers')
    return false
  end

  initial_server_facts = on(server, facter(['-y', '-p'] + facts_to_query))
  unless initial_server_facts.exit_code == 0
    warn('WARNING: facter failed during dump_sshd_ciphers')
    return false
  end

  # compile
  sshd_info = Hash[Hash[sshd_t_output.stdout.split("\n").map { |x| x.split(' ') }].map { |k, v| [k, v.split(',')] }]
  facts = Hash[Hash[initial_server_facts.stdout.split("\n").map { |x| x.split(': ') }].map { |k, v| [k, v.delete('"')] }]
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
  lines << "- ipa: #{facts['ipa'] unless facts['ipa'].empty?}"
  lines << "\n"
  lines << 'Ciphers:'
  lines << sshd_info['ciphers'].map { |x| "- `#{x}`" }
  lines << "\n"
  lines << 'MACs:'
  lines << sshd_info['macs'].map { |x| "- `#{x}`" }
  lines << "\n"
  lines << 'kexalgorithms:'
  lines << sshd_info['kexalgorithms'].map { |x| "- `#{x}`" }
  unless text.empty?
    lines << "\n"
    lines << text
  end
  report = lines.join("\n")

  # report
  warn '', report, ''
  report_dir = ENV.fetch('SIMP_SSH_report_dir', '')
  return unless File.directory?(report_dir)
  report_file = File.join(report_dir, "#{id_string}.md")
  File.write(report_file, report)
  warn("dumped sshd -T summary to '#{report_file}'")
end
