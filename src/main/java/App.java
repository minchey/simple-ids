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

    private static Map<String, String> ipToMac = new HashMap<>();
    private static Map<String, String> macToIp = new HashMap<>();
    private static String gatewayMac = null;

    public static void main(String[] args) throws Exception {

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

        // ★ OS에 따라 NIC 찾기 로직 분기
        PcapNetworkInterface nif = findNicAuto(info.interfaceName);
        if (nif == null) return;

        PcapHandle handle = nif.openLive(
                65536,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                10
        );

        String myMac = getMyMacAddress(nif);
        if (myMac == null) {
            System.err.println("MAC 주소를 찾을 수 없습니다.");
            return;
        }
        System.out.println("내 MAC = " + myMac);

        sendArpRequest(handle, info.ip, myMac, info.gateway);
        Thread.sleep(300);

        System.out.println("\n[+] ARP 기반 IDS 감지 시작…\n");

        while (true) {
            try {
                Packet raw = handle.getNextPacketEx();
                EthernetPacket ether = raw.get(EthernetPacket.class);
                if (ether == null) continue;

                Packet inner = ether.getPayload();
                if (!(inner instanceof ArpPacket)) continue;

                ArpPacket arp = inner.get(ArpPacket.class);
                ArpPacket.ArpHeader ah = arp.getHeader();

                String srcIp = ah.getSrcProtocolAddr().getHostAddress();
                String dstIp = ah.getDstProtocolAddr().getHostAddress();
                String senderMac = ah.getSrcHardwareAddr().toString();

                // LAN 범위 체크
                if (!NetworkCalc.isSameNetwork(info.ip, srcIp, info.subnetMask) &&
                        !NetworkCalc.isSameNetwork(info.ip, dstIp, info.subnetMask)) {
                    continue;
                }

                // 1) 게이트웨이 MAC 학습
                if (srcIp.equals(info.gateway) && gatewayMac == null) {
                    gatewayMac = senderMac;
                    System.out.println("📌 게이트웨이 MAC 학습됨 → " + gatewayMac);
                }

                // 2) 게이트웨이 스푸핑 탐지
                if (srcIp.equals(info.gateway) && gatewayMac != null) {
                    if (!senderMac.equals(gatewayMac)) {
                        System.out.println("🚨🚨 [심각] 게이트웨이 ARP 스푸핑 감지!");
                        System.out.println("정상 MAC: " + gatewayMac);
                        System.out.println("공격 MAC: " + senderMac);
                    }
                }

                // 3) 일반 스푸핑 탐지: IP → MAC
                if (ipToMac.containsKey(srcIp) && !ipToMac.get(srcIp).equals(senderMac)) {
                    System.out.println("⚠️ [경고] 동일 IP에서 MAC 변경 감지!");
                    System.out.println("IP = " + srcIp);
                    System.out.println("기존 MAC = " + ipToMac.get(srcIp));
                    System.out.println("신규 MAC = " + senderMac);
                }
                ipToMac.put(srcIp, senderMac);

                // MAC → IP
                if (macToIp.containsKey(senderMac) && !macToIp.get(senderMac).equals(srcIp)) {
                    System.out.println("⚠️ [주의] 동일 MAC에서 IP 변경 감지!");
                    System.out.println("MAC = " + senderMac);
                    System.out.println("기존 IP = " + macToIp.get(senderMac));
                    System.out.println("신규 IP = " + srcIp);
                }
                macToIp.put(senderMac, srcIp);

                // 디버그 출력
                System.out.println("=== ARP 탐지 (LAN) ===");
                System.out.println("Sender IP = " + srcIp);
                System.out.println("Sender MAC = " + senderMac);
                System.out.println("Target IP = " + dstIp);
                System.out.println("======================");

            } catch (TimeoutException e) {
                // ignore
            }
        }
    }

    // ========================================================================
    //  OS 자동 감지하여 NIC 찾기
    // ========================================================================
    private static PcapNetworkInterface findNicAuto(String interfaceName) throws PcapNativeException {
        String os = System.getProperty("os.name").toLowerCase();

        // ----------------------
        // ✔ macOS 전용 로직
        // ----------------------
        if (os.contains("mac")) {
            for (PcapNetworkInterface dev : Pcaps.findAllDevs()) {
                String devName = dev.getName();
                if (devName != null && devName.equals(interfaceName)) {
                    System.out.println("[macOS NIC 선택됨] " + dev.getName());
                    return dev;
                }
            }
            System.err.println("macOS에서 NIC을 찾지 못했습니다: " + interfaceName);
            return null;
        }


        // ----------------------
        // ✔ Windows / Linux (기존 방식)
        // ----------------------
        for (PcapNetworkInterface dev : Pcaps.findAllDevs()) {
            if (dev.getDescription() != null && dev.getDescription().contains(interfaceName)) {
                System.out.println("[NIC 선택됨] " + dev.getName());
                return dev;
            }
        }

        System.err.println("NIC을 찾지 못했습니다: " + interfaceName);
        return null;
    }

    // ========================================================================
    // MAC 주소 가져오기
    // ========================================================================
    private static String getMyMacAddress(PcapNetworkInterface nif) {
        for (org.pcap4j.util.LinkLayerAddress addr : nif.getLinkLayerAddresses()) {
            if (addr instanceof MacAddress) {
                return addr.toString();
            }
        }
        return null;
    }

    // ========================================================================
    // ARP Request 전송
    // ========================================================================
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
