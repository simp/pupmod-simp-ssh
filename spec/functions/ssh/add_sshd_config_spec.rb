require 'spec_helper'

describe 'ssh::add_sshd_config' do
  key_info = {
    'string'  => [ 'AuthorizedKeysFile', '/etc/ssh/local_keys/%u' ],
    'array'   => [ 'AcceptEnv', [ 'LANG', 'LC_CTYPE' ] ],
    'integer' => [ 'ClientAliveCountMax', 0 ],
  }

  context 'with undef remove_keys' do
    key_info.each do |type, key_value|
      it "creates sshd_config resource with #{type} value" do
        key = key_value[0]
        value = key_value[1]
        is_expected.to run.with_params(key, value, nil)

        # verify resource exists
        resource = catalogue.resource('Sshd_config', key)
        expect(resource).not_to be_nil
        expect(resource[:value]).to eq(value)
        # The service is notified via `ssh::server`'s class-level subscribe, so
        # the helper no longer notifies by default.
        expect(resource[:notify].to_s).to eq('[]')
      end
    end
  end

  context 'with remove_keys no match' do
    it 'creates sshd_config resource with value set' do
      key = 'ClientAliveCountMax'
      value = 1
      remove_keys = [ 'AcceptEnv', 'AuthorizedKeysFile' ]
      is_expected.to run.with_params(key, value, remove_keys)
      resource = catalogue.resource('Sshd_config', key)
      expect(resource).not_to be_nil
      expect(resource[:value]).to eq(value)
      expect(resource[:notify].to_s).to eq('[]')
    end
  end

  context 'with remove_keys match' do
    it 'does not create sshd_config resource' do
      key = 'ClientAliveCountMax'
      value = 1
      remove_keys = [ 'AcceptEnv', 'ClientAliveCountMax' ]
      is_expected.to run.with_params(key, value, remove_keys)
      resource = catalogue.resource('Sshd_config', key)
      expect(resource).to be_nil
    end
  end

  context 'with an undef value' do
    it 'does not create a sshd_config resource' do
      is_expected.to run.with_params('ClientAliveCountMax', nil, nil)
      expect(catalogue.resource('Sshd_config', 'ClientAliveCountMax')).to be_nil
    end
  end

  context 'on EL9+' do
    let(:facts) { { os: { 'release' => { 'major' => '9' } } } }
    let(:dropin) { '/etc/ssh/sshd_config.d/00-simp.conf' }

    it 'writes a first-wins keyword to the drop-in and declares it' do
      is_expected.to run.with_params('PermitRootLogin', 'no', nil)
      resource = catalogue.resource('Sshd_config', 'PermitRootLogin')
      expect(resource[:target]).to eq(dropin)
      expect(resource[:require].map(&:to_s)).to include("File[#{dropin}]")

      file = catalogue.resource('File', dropin)
      expect(file).not_to be_nil
      expect(file[:ensure]).to eq('file')
      expect(file[:mode]).to eq('0600')
      expect(file[:owner]).to eq('root')
      expect(file[:group]).to eq('root')
      expect(file[:selinux_ignore_defaults]).to be(true)
    end

    it 'declares the drop-in once for several keywords' do
      is_expected.to run.with_params('PermitRootLogin', 'no', nil)
      is_expected.to run.with_params('X11Forwarding', 'no', nil)
      expect(catalogue.resources.count { |r| r.type == 'File' && r.title == dropin }).to eq(1)
    end

    ['Port', 'AllowUsers', 'Ciphers'].each do |key|
      it "leaves #{key} in sshd_config and declares no drop-in" do
        is_expected.to run.with_params(key, ['x'], nil)
        expect(catalogue.resource('Sshd_config', key)[:target]).to be_nil
        expect(catalogue.resource('File', dropin)).to be_nil
      end
    end
  end

  context 'on EL8' do
    let(:facts) { { os: { 'release' => { 'major' => '8' } } } }

    it 'writes to sshd_config and declares no drop-in' do
      is_expected.to run.with_params('PermitRootLogin', 'no', nil)
      expect(catalogue.resource('Sshd_config', 'PermitRootLogin')[:target]).to be_nil
      expect(catalogue.resource('File', '/etc/ssh/sshd_config.d/00-simp.conf')).to be_nil
    end
  end

  context 'with no resource notification specified' do
    it 'creates sshd_config resource without notify' do
      key = 'ClientAliveCountMax'
      value = 1
      is_expected.to run.with_params(key, value, nil, [])
      resource = catalogue.resource('Sshd_config', key)
      expect(resource).not_to be_nil
      expect(resource[:value]).to eq(value)
      expect(resource[:notify].to_s).to eq('[]')
    end
  end
end
