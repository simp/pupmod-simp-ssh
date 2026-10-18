# frozen_string_literal: true

# `Simp::RspecPuppetFacts#on_supported_os` only returns operating systems for
# which simp-rspec-puppet-facts ships a SIMP factset, and it has none for
# Ubuntu.  This adds every OS release in metadata.json that it skipped, using
# the upstream rspec-puppet-facts (FacterDB) factsets, so that each
# `on_supported_os` loop also covers those releases.
#
# FacterDB factsets don't carry this module's custom facts, so the values the
# specs rely on are filled in from what the stock packages report (Ubuntu
# 22.04: OpenSSH 8.9; Ubuntu 24.04: OpenSSH 9.6; RSA, ECDSA and Ed25519 host
# keys).
module SshSpecSupportedOsFacts
  OPENSSH_VERSIONS = {
    'ubuntu-22.04' => '8.9',
    'ubuntu-24.04' => '9.6',
  }.freeze

  def on_supported_os(opts = {})
    simp_facts = super
    supported  = opts.fetch(:supported_os) { RspecPuppetFacts.meta_supported_os }

    missing = supported_os_strings(opts, simp_facts.keys) - simp_facts.keys
    return simp_facts if missing.empty?

    missing_os = supported.filter_map do |os|
      releases = Array(os['operatingsystemrelease']).select do |rel|
        missing.any? { |m| m.start_with?("#{os['operatingsystem'].downcase.gsub(%r{\s}, '_')}-#{rel}-") }
      end
      os.merge('operatingsystemrelease' => releases) unless releases.empty?
    end

    extra = Simp::RspecPuppetFacts::Shim.on_supported_os(opts.merge(supported_os: missing_os))
    extra.each do |os, facts|
      facts[:fips_enabled] = false unless facts.key?(:fips_enabled)
      facts[:ssh_host_keys] ||= [
        '/etc/ssh/ssh_host_rsa_key',
        '/etc/ssh/ssh_host_ecdsa_key',
        '/etc/ssh/ssh_host_ed25519_key',
      ]
      version = OPENSSH_VERSIONS.find { |prefix, _| os.start_with?("#{prefix}-") }
      facts[:openssh_version] ||= version.last if version
      # SIMP factsets also carry these legacy facts, which
      # ssh::global_known_hosts reads.
      facts[:fqdn] ||= facts.dig(:networking, 'fqdn')
      facts[:sshrsakey] ||= facts.dig(:ssh, 'rsa', 'key')
    end

    simp_facts.merge(extra)
  end

  # SIMP factsets use Symbol keys throughout; FacterDB factsets use String
  # keys below the top level.
  def os_family(facts)
    facts[:os][:family] || facts[:os]['family']
  end
end

include SshSpecSupportedOsFacts
