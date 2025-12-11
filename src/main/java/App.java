import network.NetworkDetector;
import network.NetworkInfo;
import network.NetworkCalc;

import org.pcap4j.core.*;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import org.pcap4j.util.MacAddress;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;

public class App {

    // IDS가 기억하는 테이블
    private static Map<String, String> ipToMac = new HashMap<>();
    private static Map<String, String> macToIp = new HashMap<>();

    // 게이트웨이의 정상 MAC (1회 학습 후 고정)
    private static String gatewayMac = null;

    public static void main(String[] args) throws Exception {

        // 1) 네트워크 정보 자동 탐지
        NetworkInfo info = NetworkDetector.detect();
        if (info == null) {
            System.err.println("네트워크 정보를 가져오지 못했습니다.");
            return;
        }

        System.out.println("===== 자동 네트워크 정보 =====");
        System.out.println("인터페이스 = " + info.interfaceName);
        System.out.println("IP = " + info.ip);
        System.out.println("Gateway = " + info.gateway);
        System.out.println("Mask = " + info.subnetMask);
        System.out.println("================================");

        // 2) pcap4j NIC 찾기
        PcapNetworkInterface nif = findNic(info.interfaceName);
        if (nif == null) return;

        // 3) 캡처 핸들 열기
        PcapHandle handle = nif.openLive(
                65536,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                10
        );

        // 4) 내 MAC 주소 알아오기
        String myMac = getMyMacAddress(nif);
        if (myMac == null) {
            System.err.println("내 MAC을 찾지 못했습니다.");
            return;
        }

        System.out.println("내 MAC = " + myMac);

        // 5) 게이트웨이 MAC 학습을 위한 ARP Request 1회 전송
        sendArpRequest(handle, info.ip, myMac, info.gateway);

        // 잠깐 대기하여 게이트웨이의 ARP Reply가 들어오도록 함
        Thread.sleep(300);

        System.out.println("\n[+] ARP 기반 IDS 감지 시작…\n");

        // 6) 메인 캡처 루프
        while (true) {
            try {

                Packet raw = handle.getNextPacketEx();
                EthernetPacket ether = raw.get(EthernetPacket.class);
                if (ether == null) continue;

                Packet inner = ether.getPayload();
                if (inner == null) continue;

                // ARP 패킷만 처리
                if (!(inner instanceof ArpPacket)) continue;

                ArpPacket arp = inner.get(ArpPacket.class);
                ArpPacket.ArpHeader ah = arp.getHeader();

                String srcIp = ah.getSrcProtocolAddr().getHostAddress();
                String dstIp = ah.getDstProtocolAddr().getHostAddress();
                String senderMac = ah.getSrcHardwareAddr().toString();

                // ◆ 먼저 LAN 범위에 포함되는지 확인
                if (!NetworkCalc.isSameNetwork(info.ip, srcIp, info.subnetMask) &&
                        !NetworkCalc.isSameNetwork(info.ip, dstIp, info.subnetMask)) {
                    continue;
                }

                // ===============================
                // 1) 게이트웨이 MAC 학습 (초기 1회)
                // ===============================
                if (srcIp.equals(info.gateway) && gatewayMac == null) {
                    gatewayMac = senderMac;
                    System.out.println("📌 게이트웨이 MAC 학습됨 → " + gatewayMac);
                }

                // ===============================
                // 2) 게이트웨이 스푸핑 탐지
                // ===============================
                if (srcIp.equals(info.gateway) && gatewayMac != null) {
                    if (!gatewayMac.equals(senderMac)) {
                        System.out.println("🚨🚨 [심각] 게이트웨이 ARP 스푸핑 감지!");
                        System.out.println("정상 MAC: " + gatewayMac);
                        System.out.println("공격 MAC: " + senderMac);
                    }
                }

                // ===============================
                // 3) ARP 테이블 기반 일반 스푸핑 탐지
                // ===============================

                // IP → MAC
                if (ipToMac.containsKey(srcIp)) {
                    String old = ipToMac.get(srcIp);
                    if (!old.equals(senderMac)) {
                        System.out.println("⚠️ [경고] 동일 IP에서 MAC 변경 감지!");
                        System.out.println("IP = " + srcIp);
                        System.out.println("기존 MAC = " + old);
                        System.out.println("신규 MAC = " + senderMac);
                    }
                }
                ipToMac.put(srcIp, senderMac);

                // MAC → IP
                if (macToIp.containsKey(senderMac)) {
                    String oldIp = macToIp.get(senderMac);
                    if (!oldIp.equals(srcIp)) {
                        System.out.println("⚠️ [주의] 동일 MAC에서 IP 변경 감지!");
                        System.out.println("MAC = " + senderMac);
                        System.out.println("기존 IP = " + oldIp);
                        System.out.println("신규 IP = " + srcIp);
                    }
                }
                macToIp.put(senderMac, srcIp);

                // ===============================
                // 디버그용 출력
                // ===============================
                System.out.println("=== ARP 탐지 (LAN) ===");
                System.out.println("Operation = " + ah.getOperation());
                System.out.println("Sender IP = " + srcIp);
                System.out.println("Sender MAC = " + senderMac);
                System.out.println("Target IP = " + dstIp);
                System.out.println("======================");

            } catch (TimeoutException e) {
                // ignore
            }
        }
    }

    // ---------------------------------------------------
    // 선택된 NIC 찾기
    // ---------------------------------------------------
    private static PcapNetworkInterface findNic(String desc) throws PcapNativeException {
        for (PcapNetworkInterface dev : Pcaps.findAllDevs()) {
            if (dev.getDescription() != null && dev.getDescription().contains(desc)) {
                System.out.println("[NIC 선택됨] " + dev.getName());
                return dev;
            }
        }
        System.err.println("NIC을 찾지 못했습니다: " + desc);
        return null;
    }

    // ---------------------------------------------------
    // NIC MAC 주소 가져오기
    // ---------------------------------------------------
    private static String getMyMacAddress(PcapNetworkInterface nif) {
        for (org.pcap4j.util.LinkLayerAddress addr : nif.getLinkLayerAddresses()) {
            if (addr instanceof MacAddress) {
                return addr.toString();
            }
        }
        return null;
    }

    // ---------------------------------------------------
    // ARP Request 전송 (1회)
    // ---------------------------------------------------
    private static void sendArpRequest(PcapHandle handle, String myIp, String myMac, String gatewayIp) throws Exception {

        MacAddress srcMac = MacAddress.getByName(myMac);
        MacAddress broadcast = MacAddress.ETHER_BROADCAST_ADDRESS;

        InetAddress srcIp = InetAddress.getByName(myIp);
        InetAddress dstIp = InetAddress.getByName(gatewayIp);

        ArpPacket.Builder arp = new ArpPacket.Builder();
        arp.hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) 6)
                .protocolAddrLength((byte) 4)
                .operation(ArpOperation.REQUEST)
                .srcHardwareAddr(srcMac)
                .srcProtocolAddr(srcIp)
                .dstHardwareAddr(MacAddress.getByName("00:00:00:00:00:00"))
                .dstProtocolAddr(dstIp);

        EthernetPacket.Builder ether = new EthernetPacket.Builder();
        ether.dstAddr(broadcast)
                .srcAddr(srcMac)
                .type(EtherType.ARP)
                .payloadBuilder(arp)
                .paddingAtBuild(true);

        handle.sendPacket(ether.build());
        System.out.println("📡 게이트웨이에 ARP Request 전송 완료");
    }
}
