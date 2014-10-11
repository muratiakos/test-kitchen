# -*- encoding: utf-8 -*-
#
# Author:: Salim Afiune (<salim@afiunemaya.com.mx>)
#
# Copyright (C) 2014, Salim Afiune
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# WORKAROUND: Avoid seeing the errors:
# => WARNING: Could not load IOV methods. Check your GSSAPI C library for an update
# => WARNING: Could not load AEAD methods. Check your GSSAPI C library for an update
# by setting $VERBOSE=nil momentarily
if defined?(WinRM).nil?
  verbose_bk = $VERBOSE
  $VERBOSE = nil
  require "winrm"
  $VERBOSE = verbose_bk
end

require "logger"

require "kitchen/errors"
require "kitchen/login_command"
require "zip"

module Kitchen

  module Transport

    # Class to help establish WinRM connections, issue remote commands, and
    # transfer files between a local system and remote node.
    #
    # @author Salim Afiune <salim@afiunemaya.com.mx>
    class Winrm < Kitchen::Transport::Base

      default_config :shell, "powershell"
      default_config :sudo, false
      default_config :max_threads, 2

      # (see Base#execute)
      def execute(command, shell = :powershell)
        return if command.nil?
        logger.debug("[#{self.class}] shell => #{shell}, (#{command})")
        exit_code, stderr = execute_with_exit(env_command(command), shell)
        if exit_code != 0 || !stderr.empty?
          raise TransportFailed,
            "Transport WinRM exited (#{exit_code}) using shell [#{shell}] for " +
              "command: [#{command}]\nREMOTE ERROR:\n" +
              human_err_msg(stderr)
        end
      end

      # Simple function that will help us running a command with an
      # specific shell without printing the output to the end user.
      #
      # @param command [String] The command to execute
      # @param shell[String] The destination file path on the guest
      # @return [Hash] Information about the STDOUT, STDERR and EXIT_CODE
      def powershell(command, shell_id = nil)
        if shell_id.nil?
          run(command, :powershell)
        else
          command = command.encode('UTF-16LE', 'UTF-8')
          command = Base64.strict_encode64(command)
          command = "powershell -encodedCommand #{command}"
          cmd(command, shell_id)
        end
      end

      def cmd(command, shell_id = nil)
        if shell_id.nil?
          run(command, :cmd)
        else
          command_id = session.run_command(shell_id, command)
          command_output = session.get_command_output(shell_id, command_id)
          session.cleanup_command(shell_id, command_id)
          command_output
        end
      end

      def wql(query)
        run(query, :wql)
      end

      # (see Base#upload!)
      def upload!(local, remote)
        logger.debug("Upload: #{local} -> #{remote}")
        local = Array.new(1) { local } if local.is_a? String
        shell_id = session.open_shell
        local.each do |path|
          if File.directory?(path)
            upload_directory(shell_id, path, remote)
          else
            upload_file(path, File.join(remote, File.basename(path)), shell_id)
          end
        end
      ensure
        session.close_shell(shell_id)
      end

      # Convert a complex CLIXML Error to a human readable format
      #
      # @param msg [String] The error message
      # @return [String] The error message with human format
      def human_err_msg(msg)
        err_msg = ""

        while msg.size > 0
          line = msg.shift
          if line.include?("CLIXML")
            msg.unshift(line)
            break
          else
            err_msg << line
          end
        end

        unless msg.empty?
          msg = msg.join
          human = msg.split(/<S S=\"Error\">/).map! do |a|
            a.gsub(/_x000D__x000A_<\/S>/, "")
          end
          human.shift
          human.pop
          err_msg << human.join("\n")
        end
        err_msg
      end

      # (see Base#login_command)
      def login_command
        rdp_file = File.join(config[:kitchen_root], ".kitchen", "#{instance.name}.rdp")
        case RUBY_PLATFORM
        when /cygwin|mswin|mingw|bccwin|wince|emx/
          # On Windows, use default RDP software
          rdp_cmd = "mstsc"
          File.open(rdp_file, "w") do |f|
            f.write(
              <<-RDP.gsub(/^ {16}/, "")
                full address:s:#{@hostname}:3389
                username:s:#{@username}
              RDP
            )
          end
          LoginCommand.new([rdp_cmd, rdp_file])
        when /darwin/
          # On MAC, we should have /Applications/Remote\ Desktop\ Connection.app
          rdc_path = "/Applications/Remote\ Desktop\ Connection.app"
          raise TransportFailed, "RDC application not found at path: #{rdc_path}" unless File.exist?(rdc_path)
          rdc_cmd = File.join(rdc_path, "Contents/MacOS/Remote\ Desktop\ Connection")
          File.open(rdp_file, "w") do |f|
            f.write(
              <<-RDP.gsub(/^ {16}/, "")
                <dict>
                  <key>ConnectionString</key>
                  <string>#{@hostname}:3389</string>
                  <key>UserName</key>
                  <string>#{@username}</string>
                </dict>
              RDP
            )
          end
          LoginCommand.new([rdc_cmd, rdp_file])
        else
          raise TransportFailed,
            "[#{self.class}] Cannot open Remote Desktop App: Unsupported platform"
        end
      end

      # (see Base#default_port)
      def default_port
        @default_port ||= 5985
      end

      private

      # (see Base#establish_connection)
      def establish_connection
        rescue_exceptions = [
          Errno::EACCES, Errno::EADDRINUSE, Errno::ECONNREFUSED,
          Errno::ECONNRESET, Errno::ENETUNREACH, Errno::EHOSTUNREACH,
          ::WinRM::WinRMHTTPTransportError, ::WinRM::WinRMAuthorizationError
        ]
        retries = 3

        begin
          logger.debug("[#{self.class}] opening connection to #{self}")
          socket = ::WinRM::WinRMWebService.new(*build_winrm_options)
          socket.set_timeout(timeout_in_seconds)
          socket
        rescue *rescue_exceptions => e
          if (retries -= 1) > 0
            logger.info("[#{self.class}] connection failed, retrying (#{e.inspect})")
            sleep 1
            retry
          else
            logger.warn("[#{self.class}] connection failed, terminating (#{e.inspect})")
            raise
          end
        end
      end

      # Timeout in seconds
      #
      # @return [Number] Timeout in seconds
      def timeout_in_seconds
        options.fetch(:timeout_in_seconds, 1800)
      end

      # String endpoint to connect thru WinRM Web Service
      #
      # @return [String] The endpoint
      def endpoint
        "http://#{@hostname}:#{port}/wsman"
      end

      # (see Base#execute_with_exit)
      def execute_with_exit(command, shell = :powershell)
        raise TransportFailed, :shell => shell unless [:powershell, :cmd, :wql].include?(shell)
        winrm_err = []
        logger.debug("[#{self.class}] #{shell} executing:\n#{command}")
        begin
          output = session.send(shell, command) do |stdout, stderr|
            logger << stdout if stdout
            winrm_err << stderr if stderr
          end
        rescue => e
          raise TransportFailed,
            "[#{self.class}] #{e.message} using shell: [#{shell}] and command: [#{command}]"
        end
        logger.debug("Output: #{output.inspect}")
        [output[:exitcode], winrm_err]
      end

      # Simple function that will help us running a command with an
      # specific shell without printing the output to the end user.
      #
      # @param command [String] The command to execute
      # @param shell[String] The destination file path on the guest
      # @return [Hash] Information about the STDOUT, STDERR and EXIT_CODE
      def run(command, shell)
        raise TransportFailed, :shell => shell unless [:powershell, :cmd, :wql].include?(shell)
        logger.debug("[#{self.class}] #{shell} running:\n#{command}")
        begin
          session.send(shell, command)
        rescue => e
          raise TransportFailed,
            "[#{self.class}] #{e.message} using shell: [#{shell}] and command: [#{command}]"
        end
      end

      # (see Base#env_command)
      def env_command(command)
        env = " $ProgressPreference='SilentlyContinue';"
        env << " $env:http_proxy=\"#{config[:http_proxy]}\";"   if config[:http_proxy]
        env << " $env:https_proxy=\"#{config[:https_proxy]}\";" if config[:https_proxy]

        env == "" ? command : "#{env} #{command}"
      end

      # (see Base#test_connection)
      def test_connection
        exitcode, _error_msg = execute_with_exit("Write-Host '[Server] Reachable...\n'", :powershell)
        exitcode.zero?
      rescue
        sleep 5
        false
      end

      # (see Base#build_transport_args)
      def build_transport_args(state)
        combined = state.to_hash.merge(config)

        opts = Hash.new
        opts[:port]           = combined[:port] if combined[:port]
        opts[:password]       = combined[:password] if combined[:password]
        opts[:forward_agent]  = combined[:forward_agent] if combined.key? :forward_agent
        opts[:logger]         = logger
        opts
      end

      # Build the WinRM options to connect
      #
      # @return endpoint [String] Information about the host and port
      # @return connection_type [String] Plaintext
      # @return options [Hash] Necesary options to connect to the remote host
      def build_winrm_options
        opts = Hash.new

        opts[:user] = username
        opts[:pass] = options[:password] if options[:password]
        opts[:host] = hostname
        opts[:port] = port
        opts[:operation_timeout] = timeout_in_seconds
        opts[:basic_auth_only] = true
        opts[:disable_sspi] = true

        [endpoint, :plaintext, opts]
      end

      def upload_file(local, remote, shell_id)
        logger.debug("Upload: #{local} -> #{remote}")
        remote = sanitize_path(remote, shell_id).strip
        if should_upload_file?(shell_id, local, remote)
          upload_to_temp_file(shell_id, local, remote)
          decode_temp_file(shell_id, local, remote)
        end
      end

      def sanitize_path(path, shell_id)
        command = <<-EOH
          $dest_file_path = [System.IO.Path]::GetFullPath('#{path}')

          if (!(Test-Path $dest_file_path)) {
            $dest_dir = ([System.IO.Path]::GetDirectoryName($dest_file_path))
            New-Item -ItemType directory -Force -Path $dest_dir | Out-Null
          }

          $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath("#{path}")
        EOH

        powershell(command, shell_id)[:data][0][:stdout]
      end

      # Checks to see if the target file on the guest is missing or out of date.
      #
      # @param [String] The source file path on the host
      # @param [String] The destination file path on the guest
      # @return [Boolean] True if the file is missing or out of date
      def should_upload_file?(shell_id, local, remote)
        logger.debug("comparing #{local} to #{remote}")
        local_md5 = Digest::MD5.file(local).hexdigest
        command = <<-EOH
$dest_file_path = [System.IO.Path]::GetFullPath('#{remote}')

if (Test-Path $dest_file_path) {
  $crypto_prov = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
  try {
    $file = [System.IO.File]::Open($dest_file_path,
      [System.IO.Filemode]::Open, [System.IO.FileAccess]::Read)
    $guest_md5 = ([System.BitConverter]::ToString($crypto_prov.ComputeHash($file)))
    $guest_md5 = $guest_md5.Replace("-","").ToLower()
  }
  finally {
    $file.Dispose()
  }
  if ($guest_md5 -eq '#{local_md5}') {
    exit 0
  }
}
remove-item $dest_file_path -Force
exit 1
        EOH
        powershell(command, shell_id)[:exitcode] == 1
      end

      # Uploads the given file to a new temp file on the guest
      #
      # @param [String] The source file path on the host
      # @return [String] The temp file path on the guest
      def upload_to_temp_file(shell_id, local, remote)
        #tmp_file_path = File.join(guest_temp_dir, "winrm-upload-#{rand}")
        logger.debug("Uploading '#{local}' to temp file '#{remote}'")
        base64_host_file = Base64.encode64(IO.binread(local)).gsub("\n", "")
        base64_host_file.chars.to_a.each_slice(8000 - remote.size) do |chunk|
          output = cmd("echo #{chunk.join} >> \"#{remote}\"", shell_id)
          raise_upload_error_if_failed(output, local, remote)
        end
      end

      # Recursively uploads the given directory from the host to the guest
      #
      # @param [String] The source file or directory path on the host
      # @param [String] The destination file or directory path on the host
      def upload_directory(shell_id, local, remote)
        zipped = zip_path(local)
        return if !File.exist?(zipped)
        remote_zip = File.join(remote, File.basename(zipped))
        logger.debug("uploading #{zipped} to #{remote_zip}")
        upload_file(zipped, remote_zip, shell_id)
        extract_zip(remote_zip, local, shell_id)
      end

      def zip_path(path)
        path.sub!(%r[/$],'')
        archive = File.join(path,File.basename(path))+'.zip'
        FileUtils.rm archive, :force=>true

        Zip::File.open(archive, 'w') do |zipfile|
          Dir["#{path}/**/**"].reject{|f|f==archive}.each do |file|
            zipfile.add(file.sub(path+'/',''),file)
          end
        end

        archive
      end


      def extract_zip(remote_zip, local, shell_id)
        logger.debug("extracting #{remote_zip} to #{remote_zip.gsub('/','\\').gsub('.zip','')}")
        command = <<-EOH
          $shellApplication = new-object -com shell.application 
          $zip_path = "$($env:systemDrive)#{remote_zip.gsub('/','\\')}"

          $zipPackage = $shellApplication.NameSpace($zip_path) 
          $dest_path = "$($env:systemDrive)#{remote_zip.gsub('/','\\').gsub('.zip','')}"
          mkdir $dest_path -ErrorAction SilentlyContinue
          $destinationFolder = $shellApplication.NameSpace($dest_path) 
          $destinationFolder.CopyHere($zipPackage.Items(),0x10)
        EOH

        output = powershell(command, shell_id)
        raise_upload_error_if_failed(output, local, remote_zip)
      end

      # Moves and decodes the given file temp file on the guest to its
      # permanent location
      #
      # @param [String] The source base64 encoded temp file path on the guest
      # @param [String] The destination file path on the guest
      def decode_temp_file(shell_id, local, remote)
        logger.debug("Decoding temp file '#{remote}'")
        command = <<-EOH
          $tmp_file_path = [System.IO.Path]::GetFullPath('#{remote}')

          $dest_dir = ([System.IO.Path]::GetDirectoryName($tmp_file_path))
          New-Item -ItemType directory -Force -Path $dest_dir

          $base64_string = Get-Content $tmp_file_path
          $bytes = [System.Convert]::FromBase64String($base64_string)
          [System.IO.File]::WriteAllBytes($tmp_file_path, $bytes)
        EOH
        output = powershell(command, shell_id)
        raise_upload_error_if_failed(output, local, remote)
      end

      # Creates a guest file path equivalent from a host file path
      #
      # @param [String] The base host directory we're going to copy from
      # @param [String] The base guest directory we're going to copy to
      # @param [String] A full path to a file on the host underneath local
      # @return [String] The guest file path equivalent
      def remote_file_path(local, remote, local_file_path)
        relative_path = File.dirname(local_file_path[local.length, local_file_path.length])
        File.join(remote, File.basename(local), relative_path, File.basename(local_file_path))
      end

      # Get the guest temporal path to upload temporal files
      #
      # @return [String] The guest temp path
      def guest_temp_dir
        @guest_temp ||= (cmd("echo %TEMP%"))[:data][0][:stdout].chomp
      end

      def raise_upload_error_if_failed(output, from, to)
        raise TransportFailed,
          :from => from,
          :to => to,
          :message => output.inspect unless output[:exitcode].zero?
      end
    end
  end
end
