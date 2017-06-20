require 'spec_helper'

describe 'ssh::autokey' do
  let(:environment) { 'testenv' }

  context 'with minimal input' do
    it { 
      # Puppet[:vardir] is dynamically created as a tmpdir by the test
      # framework, when the subject is first created. So create the
      # subject now to retrieve that setting for use in our expectations
      # within this example block.
      subject()
      vardir = Puppet[:vardir]
      ssh_autokeys_dir = File.join(vardir, 'simp', 'environments', environment,
        'simp_autofiles', 'ssh_autokeys')
      user_private_keyfile = File.join(ssh_autokeys_dir, 'user1')
      user_public_keyfile = File.join(ssh_autokeys_dir, 'user1.pub')

      expect(! File.exist?(ssh_autokeys_dir))

      # first time through, will create directories and public/private
      # key files
      is_expected.to run.with_params('user1')
      expect(File.exist?(ssh_autokeys_dir))
      expect(File.exist?(user_private_keyfile))
      expect(File.exist?(user_public_keyfile))
      actual_key_len = `ssh-keygen -lf #{user_public_keyfile}`.split[0].to_i    
      expect(actual_key_len).to eq(2048)

      # second time through will read existing key files
      public_key = IO.read(user_public_keyfile).strip
      is_expected.to run.with_params('user1').and_return(public_key.gsub('ssh-rsa ',''))
    }
  end

  context 'with non-hash optional parameters' do
    it { 
      # Puppet[:vardir] is dynamically created as a tmpdir by the test
      # framework, when the subject is first created. So create the
      # subject now to retrieve that setting for use in our expectations
      # within this example block.
      subject()
      vardir = Puppet[:vardir]
      ssh_autokeys_dir = File.join(vardir, 'simp', 'environments', environment,
        'simp_autofiles', 'ssh_autokeys')
      user_private_keyfile = File.join(ssh_autokeys_dir, 'user1')
      user_public_keyfile = File.join(ssh_autokeys_dir, 'user1.pub')

      expect(! File.exist?(ssh_autokeys_dir))

      # first time through, will create directories and public/private
      # key files
      is_expected.to run.with_params('user1', 3072, true)
      expect(File.exist?(ssh_autokeys_dir))
      expect(File.exist?(user_private_keyfile))
      expect(File.exist?(user_public_keyfile))
      actual_key_len = `ssh-keygen -lf #{user_public_keyfile}`.split[0].to_i    
      expect(actual_key_len).to eq(3072)

      # second time through will read existing key files
      private_key = IO.read(user_private_keyfile)
      is_expected.to run.with_params('user1', 3072, true).and_return(private_key)
    }
  end

  context 'with hash optional parameter' do
    let(:options) {{'key_strength'=>4096, 'return_private' => true }}
    it { 
      # Puppet[:vardir] is dynamically created as a tmpdir by the test
      # framework, when the subject is first created. So create the
      # subject now to retrieve that setting for use in our expectations
      # within this example block.
      subject()
      vardir = Puppet[:vardir]
      ssh_autokeys_dir = File.join(vardir, 'simp', 'environments', environment,
        'simp_autofiles', 'ssh_autokeys')
      user_private_keyfile = File.join(ssh_autokeys_dir, 'user1')
      user_public_keyfile = File.join(ssh_autokeys_dir, 'user1.pub')

      expect(! File.exist?(ssh_autokeys_dir))

      # first time through, will create directories and public/private
      # key files
      is_expected.to run.with_params('user1', options)
      expect(File.exist?(ssh_autokeys_dir))
      expect(File.exist?(user_private_keyfile))
      expect(File.exist?(user_public_keyfile))
      actual_key_len = `ssh-keygen -lf #{user_public_keyfile}`.split[0].to_i    
      expect(actual_key_len).to eq(4096)

      # second time through will read existing key files
      private_key = IO.read(user_private_keyfile)
      is_expected.to run.with_params('user1', options).and_return(private_key)
    }
  end
end
