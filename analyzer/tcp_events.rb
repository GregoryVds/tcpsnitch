class TcpEvent
  @@events_count = {}
  
  def initialize(hash)
    count_event(hash['type'])
  end

  def count_event(type)
    if @@events_count.key?(type) then
      @@events_count[type] += 1
    else
      @@events_count[type] = 0
    end
  end

  def self.print_events
    pp @@events_count
  end
end

class TcpEvSocket < TcpEvent; end
class TcpEvBind < TcpEvent; end
class TcpEvConnect < TcpEvent; end
class TcpEvShutdown < TcpEvent; end
class TcpEvListen < TcpEvent; end
class TcpEvSetsockopt < TcpEvent; end
class TcpEvSend < TcpEvent; end
class TcpEvRecv < TcpEvent; end
class TcpEvSendto < TcpEvent; end
class TcpEvRecvfrom < TcpEvent; end
class TcpEvSendmsg < TcpEvent; end
class TcpEvRecvMsg < TcpEvent; end
class TcpEvClose < TcpEvent; end
class TcpEvWrite < TcpEvent; end
class TcpEvRead < TcpEvent; end
class TcpEvWritev < TcpEvent; end
class TcpEvReadv < TcpEvent; end
class TcpEvTcpInfo < TcpEvent; end
