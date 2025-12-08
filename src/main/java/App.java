import network.NetworkDetector;
import network.NetworkInfo;

import org.pcap4j.core.*;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.TimeoutException;

public class App {

    public static void main(String[] args) throws PcapNativeException {

        // 1) 운영체제별 NIC/IP/Mask/Gateway 자동 탐지
        NetworkInfo info = NetworkDetector.detect();


        if (info == null) {
            System.err.println("네트워크 정보를 가져오지 못했습니다.");
            return;
        }

        System.out.println("===== 자동 네트워크 정보 =====");
        System.out.println("인터페이스 이름 = " + info.interfaceName);
        System.out.println("IP 주소 = " + info.ip);
        System.out.println("게이트웨이 = " + info.gateway);
        System.out.println("서브넷 마스크 = " + info.subnetMask);
        System.out.println("==============================");

        // 2) pcap4j NIC 객체 가져오기
        String winDesc = info.interfaceName;   // 예: "Realtek PCIe GbE Family Controller"

        PcapNetworkInterface nif = null;

        // 2) 모든 NIC 목록 확인
        for (PcapNetworkInterface dev : Pcaps.findAllDevs()) {
            if (dev.getDescription() != null && dev.getDescription().contains(winDesc)) {
                nif = dev;
                break;
            }
        }

        if (nif == null) {
            System.err.println("Pcap4j에서 NIC을 찾지 못했습니다: " + winDesc);
            return;
        }

        System.out.println("[PCAP4J 선택된 NIC]");
        System.out.println("Name = " + nif.getName());
        System.out.println("Description = " + nif.getDescription());

        if (nif == null) {
            System.err.println("Pcap4j에서 NIC을 찾지 못했습니다: " + info.interfaceName);
            return;
        }

        // 3) 패킷 캡처 핸들 열기
        PcapHandle handle = nif.openLive(
                65536,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                10
        );

        System.out.println("[+] 실시간 ARP 기반 IDS 패킷 캡처 시작…");

        // 4) 메인 캡처 루프
        while (true) {
            try {
                Packet raw = handle.getNextPacketEx();

                EthernetPacket ether = raw.get(EthernetPacket.class);
                if (ether == null) continue;

                Packet inner = ether.getPayload();
                if (inner == null) continue;

                // ★ ARP 탐지
                if (inner instanceof ArpPacket) {
                    ArpPacket arp = inner.get(ArpPacket.class);
                    ArpPacket.ArpHeader ah = arp.getHeader();

                    System.out.println("========== ARP 탐지 ==========");
                    System.out.println("종류(Operation) → " + ah.getOperation());
                    System.out.println("보낸 MAC(Source MAC) → " + ah.getSrcHardwareAddr());
                    System.out.println("보낸 IP(Source IP) → " + ah.getSrcProtocolAddr());
                    System.out.println("대상 IP(Target IP) → " + ah.getDstProtocolAddr());
                    System.out.println("대상 MAC(Target MAC) → " + ah.getDstHardwareAddr());
                    System.out.println("프로토콜 → ArpPacket");
                }

            } catch (TimeoutException e) {
                // 패킷이 일정 시간 동안 없을 때 발생하는 예외 → 무시 가능
            }
            catch (Exception e){
                e.printStackTrace();
            }
        }
    }
}
