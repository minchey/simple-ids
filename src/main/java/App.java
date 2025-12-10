import network.NetworkDetector;
import network.NetworkInfo;
import network.NetworkCalc;

import org.pcap4j.core.*;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;

public class App {

    // ARP 기록 저장하는 테이블 (IDS의 기억력)
    private static Map<String, String> ipToMac = new HashMap<>(); //final은 참조변경이 되지 않아 초기화시 필요하므로 final x
    private static Map<String, String> macToIp = new HashMap<>();

    // 게이트웨이 MAC(처음 이후 계속 비교)
    private static String gatewayMac = null;

    public static void main(String[] args) throws PcapNativeException {

        //기본 네트워크 정보 가져오기
        //운영체제별 NIC/IP/Mask/Gateway 자동 탐지
        NetworkInfo info = NetworkDetector.detect();
        if (info == null) {
            System.err.println("네트워크 정보를 가져오지 못했습니다.");
            return;
        }

        System.out.println("===== 자동 네트워크 정보 =====");
        System.out.println("인터페이스 = " + info.interfaceName);
        System.out.println("IP = " + info.ip);
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

                    String srcIp = ah.getSrcProtocolAddr().getHostAddress();
                    String dstIp = ah.getDstProtocolAddr().getHostAddress();



                    boolean srcInLan = NetworkCalc.isSameNetwork(info.ip, srcIp, info.subnetMask);
                    boolean dstInLan = NetworkCalc.isSameNetwork(info.ip, dstIp, info.subnetMask);

                    // LAN 범위 밖이라면 그냥 스킵
                    if (!srcInLan && !dstInLan) {
                        continue;
                    }

                    // ★ IDS에서 분석할 핵심 값 2개
                    String senderIp = srcIp;
                    String senderMac = ah.getSrcHardwareAddr().toString();

                    // 1) IP → MAC 기록
                    if (!ipToMac.containsKey(senderIp)) {
                        ipToMac.put(senderIp, senderMac);
                    } else {
                        String oldMac = ipToMac.get(senderIp);
                        if (!oldMac.equals(senderMac)) {
                            System.out.println("🚨 [경고] 동일 IP에서 MAC 변경 감지!");
                            System.out.println("IP: " + senderIp);
                            System.out.println("기존 MAC: " + oldMac);
                            System.out.println("새 MAC: " + senderMac);
                            ipToMac.put(senderIp, senderMac);

                        }
                    }

                    // 2) MAC → IP 기록
                    if (!macToIp.containsKey(senderMac)) {
                        macToIp.put(senderMac, senderIp);
                    } else {
                        String oldIp = macToIp.get(senderMac);
                        if (!oldIp.equals(senderIp)) {
                            System.out.println("⚠️ [주의] 동일 MAC에서 IP 변경 감지");
                            System.out.println("MAC: " + senderMac);
                            System.out.println("기존 IP: " + oldIp);
                            System.out.println("새 IP: " + senderIp);
                            macToIp.put(senderMac, senderIp);
                        }
                    }

                    // LAN 내부 ARP 패킷
                    System.out.println("========== ARP 탐지 (LAN 내) ==========");
                    System.out.println("종류(Operation) → " + ah.getOperation());
                    System.out.println("보낸 MAC(Source MAC) → "
                            + senderMac);
                    System.out.println("보낸 IP(Source IP) → " + senderIp);
                    System.out.println("대상 IP(Target IP) → " + dstIp);
                    System.out.println("대상 MAC(Target MAC) → " + ah.getDstHardwareAddr());
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
