import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;


public class App {
    public static void main(String[] args) throws PcapNativeException{
        // 1) 모든 네트워크 인터페이스 목록 가져오기
        var interfaces = Pcaps.findAllDevs();

        // 2) 네트워크 인터페이스 출력
        for(var nif : interfaces){
            System.out.println("- " + nif.getName() + " : " + nif.getDescription());
        }
    }
}
