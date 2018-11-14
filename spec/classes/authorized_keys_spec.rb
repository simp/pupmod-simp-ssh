require 'spec_helper'

describe 'ssh::authorized_keys' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts
      end

      let(:str)  {{ 'kelly' => 'ssh-rsa skjfhslkdjfs...' }}
      let(:str2) {{ 'dave' => 'ssh-rsa fiqsuouefa... dave@test.local' }}
      let(:ary)  {{
        'nick' => [
          'ssh-rsa sajhgfsaihd... nick@test.local',
          'ssh-rsa jrklsahsgfs... nick',
          'ssh-rsa ffioqlasasd...'
        ]
      }}
      let(:hash) {{
        'mike' => {
          'key'    => 'dlfkjsahh...',
          'type'   => 'ssh-rsa',
          'user'   => 'mlast',
          'target' => '/etc/ssh/local_keys/mlast'
        }
      }}

      it { is_expected.to create_class('ssh::authorized_keys') }
      it { is_expected.to compile.with_all_deps }

      context 'with a $keys hash with short string entries' do
        let(:params) {{ :keys => str }}

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_ssh_authorized_key('kelly - skjfh...').with(
          'user' => 'kelly',
          'type' => 'ssh-rsa',
          'key'  => 'skjfhslkdjfs...',
        ) }
      end

      context 'with a $keys hash with normal string entries' do
        let(:params) {{ :keys => str2 }}

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_ssh_authorized_key('dave - fiqsu...').with(
          'user' => 'dave',
          'type' => 'ssh-rsa',
          'key'  => 'fiqsuouefa...',
        ) }
      end

      context 'with a $keys hash with array entries' do
        let(:params) {{ :keys => ary }}

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_ssh_authorized_key('nick - sajhg...').with(
          'user' => 'nick',
          'type' => 'ssh-rsa',
          'key'  => 'sajhgfsaihd...',
        ) }
        it { is_expected.to create_ssh_authorized_key('nick - jrkls...').with(
          'user' => 'nick',
          'type' => 'ssh-rsa',
          'key'  => 'jrklsahsgfs...',
        ) }
        it { is_expected.to create_ssh_authorized_key('nick - ffioq...').with(
          'user' => 'nick',
          'type' => 'ssh-rsa',
          'key'  => 'ffioqlasasd...',
        ) }
      end

      context 'with a $keys hash with hash entries' do
        let(:params) {{ :keys => hash }}

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_ssh_authorized_key('mike').with(
          'key'    => 'dlfkjsahh...',
          'type'   => 'ssh-rsa',
          'user'   => 'mlast',
          'target' => '/etc/ssh/local_keys/mlast'
        ) }
      end

      context 'with a $keys hash with all types of entries' do
        let(:params) {{ :keys => str.merge(str2.merge(ary.merge(hash))) }}

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_ssh_authorized_key('dave - fiqsu...').with(
          'user' => 'dave',
          'type' => 'ssh-rsa',
          'key'  => 'fiqsuouefa...',
        ) }
        it { is_expected.to create_ssh_authorized_key('kelly - skjfh...').with(
          'user' => 'kelly',
          'type' => 'ssh-rsa',
          'key'  => 'skjfhslkdjfs...',
        ) }
        it { is_expected.to create_ssh_authorized_key('nick - sajhg...').with(
          'user' => 'nick',
          'type' => 'ssh-rsa',
          'key'  => 'sajhgfsaihd...',
        ) }
        it { is_expected.to create_ssh_authorized_key('nick - jrkls...').with(
          'user' => 'nick',
          'type' => 'ssh-rsa',
          'key'  => 'jrklsahsgfs...',
        ) }
        it { is_expected.to create_ssh_authorized_key('nick - ffioq...').with(
          'user' => 'nick',
          'type' => 'ssh-rsa',
          'key'  => 'ffioqlasasd...',
        ) }
        it { is_expected.to create_ssh_authorized_key('mike').with(
          'key'    => 'dlfkjsahh...',
          'type'   => 'ssh-rsa',
          'user'   => 'mlast',
          'target' => '/etc/ssh/local_keys/mlast'
        ) }
      end
    end
  end
end
