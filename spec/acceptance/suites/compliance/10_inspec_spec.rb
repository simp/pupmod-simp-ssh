require 'spec_helper_acceptance'
require 'json'

test_name 'Check Inspec'

describe 'run inspec against the appropriate fixtures' do
  profiles_to_validate = ['disa_stig']
  # This is a hack for tests that have both pam and ssh
  # aspects.  This will make the pam part of the test pass
  # V-72245, V-72275
  let(:pam_sshd_content) { File.read(File.join(File.dirname(__FILE__), 'files', 'pam_sshd')) }
  let(:manifest) do
    <<-EOS

     file { '/etc/pam.d/sshd':
       ensure => file,
       content => "#{pam_sshd_content}",
       owner   => 'root',
       mode    => '0644'
     }
    EOS
  end

  hosts.each do |host|
    profiles_to_validate.each do |profile|
      context "for profile #{profile}" do
        context "on #{host}" do
          # rubocop:disable RSpec/InstanceVariable
          before(:all) do
            @inspec = Simp::BeakerHelpers::Inspec.new(host, profile)
            @inspec_report = { data: nil }
          end

          it 'applies the hack to make the pam test pass' do
            apply_manifest_on(host, manifest, catch_failures: false)
          end

          it 'runs inspec' do
            @inspec.run
          end

          it 'has an inspec report' do
            @inspec_report[:data] = @inspec.process_inspec_results

            info = [
              'Results:',
              "  * Passed: #{@inspec_report[:data][:passed]}",
              "  * Failed: #{@inspec_report[:data][:failed]}",
              "  * Skipped: #{@inspec_report[:data][:skipped]}",
            ]

            puts info.join("\n")

            @inspec.write_report(@inspec_report[:data])
          end

          it 'has run some tests' do
            expect(@inspec_report[:data][:failed] + @inspec_report[:data][:passed]).to be > 0
          end

          it 'does not have any failing tests' do
            if @inspec_report[:data][:failed] > 0
              puts @inspec_report[:data][:report]
            end

            expect(@inspec_report[:data][:failed]).to eq(0)
          end
          # rubocop:enable RSpec/InstanceVariable
        end
      end
    end
  end
end
