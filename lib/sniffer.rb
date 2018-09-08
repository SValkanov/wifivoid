require_relative 'dot11_packet'
require 'socket'

class Sniffer
  def initialize
    @socket = Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, 0x0300)
  end

  def receive_packet
    pkt = Dot11Packet.new(@socket.recvfrom(2048)[0])
    pkt.parse
    pkt
  end
end
