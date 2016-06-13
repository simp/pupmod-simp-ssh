require 'spec_helper'

shared_examples_for "an ssh server" do
  it { is_expected.to create_class('ssh::server') }
  it { is_expected.to compile.with_all_deps }
  it { is_expected.to contain_class('ssh') }

  it { is_expected.to create_file('/var/empty/sshd').with({
      :ensure  => 'directory',
      :require => 'Package[openssh-server]'
    })
  }

  it { is_expected.to create_file('/var/empty/sshd/etc').with({
      :ensure  => 'directory',
      :require => 'Package[openssh-server]'
    })
  }

  it { is_expected.to create_file('/var/empty/sshd/etc/localtime').with({
      :source  => '/etc/localtime',
      :require => 'Package[openssh-server]'
    })
  }

  it { is_expected.to contain_group('sshd') }

  it { is_expected.to contain_package('openssh-server').with_ensure('latest') }

  it { is_expected.to contain_user('sshd').with({
      :ensure    => 'present',
      :allowdupe => false,
      :gid       => '74',
      :uid       => '74'
    })
  }

  it { is_expected.to contain_service('sshd').with({
      :ensure  => 'running',
      :require => 'Package[openssh-server]'
    })
  }

  it { is_expected.to_not contain_exec('SELinux Allow SSH Port 22') }

end

describe 'ssh::server' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end
        let(:facts) { facts.merge( { :openssh_version => '6.6' } ) }

        context "with default parameters" do
          it_behaves_like "an ssh server"

          if (['RedHat', 'CentOS'].include?(facts[:operatingsystem]))
            if (facts[:operatingsystemmajrelease].to_s >= '7')

              context "with fips enabled" do
                let(:facts) { facts.merge( { :fips_enabled => true, :openssh_version => '6.6' } ) }
                it { is_expected.to contain_sshd_config('Ciphers').with_value(
                     ['aes256-gcm@openssh.com',
                      'aes128-gcm@openssh.com'])
                }
                it { is_expected.to contain_sshd_config('MACs').with_value(
                     ['hmac-sha2-256',
                     'hmac-sha1'])
                }
                context "with openssh_version 6.6" do
                  it { is_expected.to contain_sshd_config('KexAlgorithms').with_value(
                       ['ecdh-sha2-nistp521',
                       'ecdh-sha2-nistp384',
                       'ecdh-sha2-nistp256',
                       'diffie-hellman-group-exchange-sha256'])
                  }
                end
                context "with openssh_version 5.6" do
                  let(:facts) { facts.merge( { :openssh_version => '5.6' } ) }
                  it { is_expected.to_not contain_sshd_config('KexAlgorithms') }
                end
              end
              context "with fips disabled" do
                let(:facts) { facts.merge( { :fips_enabled => false, :openssh_version => '6.6' } ) }
                it { is_expected.to contain_sshd_config('Ciphers').with_value(
                     ['aes256-gcm@openssh.com',
                      'aes128-gcm@openssh.com'])
                }
                it { is_expected.to contain_sshd_config('MACs').with_value(
                     ['hmac-sha2-512-etm@openssh.com',
                     'hmac-sha2-256-etm@openssh.com',
                     'hmac-sha2-512',
                     'hmac-sha2-256'])
                }
                context "with openssh_version 6.6" do
                  it { is_expected.to contain_sshd_config('KexAlgorithms').with_value(
                       ['curve25519-sha256@libssh.org',
                       'ecdh-sha2-nistp521',
                       'ecdh-sha2-nistp384',
                       'ecdh-sha2-nistp256',
                       'diffie-hellman-group-exchange-sha256'])
                  }
                end
                context "with openssh_version 6.4" do
                  let(:facts) { facts.merge( { :openssh_version => '6.4' } ) }
                  it { is_expected.to contain_sshd_config('KexAlgorithms').with_value(
                       ['ecdh-sha2-nistp521',
                       'ecdh-sha2-nistp384',
                       'ecdh-sha2-nistp256',
                       'diffie-hellman-group-exchange-sha256'])
                  }
                end
                context "with openssh_version 5.6" do
                  let(:facts) { facts.merge( { :openssh_version => '5.6' } ) }
                  it { is_expected.to_not contain_sshd_config('KexAlgorithms') }
                end

                it { is_expected.to_not contain_package('openssh-ldap').with_ensure('latest') }
                it { is_expected.not_to contain_sshd_config('Ciphers').with_value(
                     ['aes256-cbc',
                      'aes192-cbc',
                      'aes128-cbc'])
                }

              end
            # Not EL 7+ OS
            else
              it { is_expected.to contain_sshd_config('Ciphers').with_value(
                   ['aes256-cbc',
                    'aes192-cbc',
                    'aes128-cbc'])
              }
              it { is_expected.to contain_sshd_config('MACs').with_value(
                   ['hmac-sha1'])
              }
              context "with openssh_version 6.6" do
                let(:facts) { facts.merge( { :openssh_version => '6.6' } ) }
                it { is_expected.to contain_sshd_config('KexAlgorithms').with_value(
                     ['diffie-hellman-group-exchange-sha256'])
                }
              end
              context "with openssh_version 5.6" do
                let(:facts) { facts.merge( { :openssh_version => '5.6' } ) }
                it { is_expected.to_not contain_sshd_config('KexAlgorithms') }
              end
            end
          end
        end

        if (facts[:operatingsystemrelease].to_s < '6.7')
          it { is_expected.to contain_package('openssh-ldap').with_ensure('latest') }
        end

        context "with enable_fallback_ciphers => true" do
          let(:pre_condition){
            "class{'ssh::server::conf': enable_fallback_ciphers => true }"
          }
          it_behaves_like "an ssh server"
          if (['RedHat', 'CentOS'].include?(facts[:operatingsystem]))
            if (facts[:operatingsystemmajrelease].to_s >= '7')
              it { is_expected.to contain_sshd_config('Ciphers').with_value(
                ['aes256-gcm@openssh.com',
                 'aes128-gcm@openssh.com',
                 'aes256-cbc',
                 'aes192-cbc',
                 'aes128-cbc'])
              }
            else
              it { is_expected.to contain_sshd_config('Ciphers').with_value(
                  ['aes256-cbc',
                   'aes192-cbc',
                   'aes128-cbc'])
              }
            end
          end
        end

        context "with use_ldap => false" do
          let(:pre_condition){
            "class{'ssh::server::conf': use_ldap => false }"
          }
          it_behaves_like "an ssh server"
          it { is_expected.to_not contain_package('openssh-ldap').with_ensure('latest') }
        end

        context "with a non-standard ssh port" do
          let(:pre_condition){
            "class{'ssh::server::conf': port => 22000 }"
          }
          it { is_expected.to contain_package('policycoreutils-python').that_comes_before('Exec[SELinux Allow SSH Port 22000]') }
          it { is_expected.to contain_exec('SELinux Allow SSH Port 22000') }
        end
      end
    end
  end
end
