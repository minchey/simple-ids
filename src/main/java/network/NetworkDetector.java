package network;

import java.io.BufferedReader;
import java.io.InputStreamReader;
public class NetworkDetector {

    public static NetworkInfo detect(){

        String os = System.getProperty("os.name").toLowerCase(); //os 뽑아와서 소문자로 정제

        if(os.contains("mac")){
            return detectMac();
        } else if (os.contains("win")) {
            return detectWin();
        } else if (os.contains("linux")) {
            return detectLinux();
        }
        return null;
    }

    private static NetworkInfo detectMac() {
        NetworkInfo info = new NetworkInfo();

        try {
            // 1) 기본 라우팅 테이블 읽기
            Process proc = Runtime.getRuntime().exec("route -n get default");
            BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {

                if (line.trim().startsWith("interface:")) {
                    info.interfaceName = line.split(":")[1].trim();
                }

                if (line.trim().startsWith("gateway:")) {
                    info.gateway = line.split(":")[1].trim();
                }
            }

            // 인터페이스 못 찾으면 실패
            if (info.interfaceName == null) return info;

            // 2) 해당 인터페이스 정보를 ifconfig에서 가져옴
            Process ifconfigProc = Runtime.getRuntime().exec("ifconfig " + info.interfaceName);
            BufferedReader ifReader = new BufferedReader(new InputStreamReader(ifconfigProc.getInputStream()));

            while ((line = ifReader.readLine()) != null) {

                line = line.trim();

                // IP
                if (line.startsWith("inet ")) {
                    String[] parts = line.split("\\s+");
                    info.ip = parts[1]; // inet 뒤의 값
                }

                // netmask
                if (line.contains("netmask")) {
                    // 예: netmask 0xffffff00
                    String[] parts = line.split("\\s+");
                    for (int i = 0; i < parts.length; i++) {
                        if (parts[i].equals("netmask")) {
                            info.subnetMask = convertHexMaskToDecimal(parts[i + 1]);
                        }
                    }
                }
            }

            return info;

        } catch (Exception e) {
            e.printStackTrace();
            return info;
        }
    }


    private static String convertHexMaskToDecimal(String hexMask) {
        long mask = Long.decode(hexMask);
        return String.format("%d.%d.%d.%d",
                (mask >> 24) & 0xFF,
                (mask >> 16) & 0xFF,
                (mask >> 8) & 0xFF,
                mask & 0xFF
        );
    }

    private static NetworkInfo detectWin() {

        NetworkInfo info = new NetworkInfo();

        try {
            // 1) 전체 NIC 정보 가져오기
            Process proc = Runtime.getRuntime().exec(new String[]{
                    "powershell.exe", "-NoLogo", "-Command",
                    "Get-NetIPConfiguration"
            });

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(proc.getInputStream(), "UTF-8")
            );

            String line;
            boolean inBlock = false;

            String ip = null;
            String gateway = null;
            String description = null;

            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;

                // NIC 블록의 시작: 항상 InterfaceAlias로 시작함
                if (line.startsWith("InterfaceAlias")) {
                    // 새 블록이 시작되므로 초기화
                    ip = null;
                    gateway = null;
                    description = null;
                    inBlock = true;
                    continue;
                }

                if (!inBlock) continue;

                // Description (pcap4j가 사용하는 NIC 매칭용)
                if (line.startsWith("InterfaceDescription")) {
                    description = line.split(":", 2)[1].trim();
                }

                // IP 주소
                if (line.startsWith("IPv4Address")) {
                    ip = line.split(":", 2)[1].trim();
                }

                // 기본 게이트웨이
                if (line.startsWith("IPv4DefaultGateway")) {
                    gateway = line.split(":", 2)[1].trim();

                    // 💡 여기서 바로 판단 가능: gateway가 있으면 "인터넷 되는 NIC"
                    if (!gateway.isEmpty()) {
                        info.ip = ip;
                        info.gateway = gateway;
                        info.interfaceName = description;
                        break; // 이 NIC가 우리가 찾던 기본 NIC → 나머지 무시
                    }
                }
            }

            if (info.ip == null || info.gateway == null || info.interfaceName == null) {
                System.err.println("기본 NIC 블록에서 정보를 완전히 얻지 못했습니다.");
                return null;
            }

            // 2) PrefixLength → CIDR → SubnetMask 변환
            Process prefixProc = Runtime.getRuntime().exec(new String[]{
                    "powershell.exe", "-NoLogo", "-Command",
                    "Get-NetIPAddress -AddressFamily IPv4"
            });

            BufferedReader pr = new BufferedReader(
                    new InputStreamReader(prefixProc.getInputStream(), "UTF-8")
            );

            while ((line = pr.readLine()) != null) {
                line = line.trim();

                if (line.startsWith("IPAddress") && line.contains(info.ip)) {

                    String prefixLine;
                    while ((prefixLine = pr.readLine()) != null) {
                        prefixLine = prefixLine.trim();
                        if (prefixLine.startsWith("PrefixLength")) {
                            int cidr = Integer.parseInt(prefixLine.split(":", 2)[1].trim());
                            info.subnetMask = cidrToMask(cidr);
                            return info;
                        }
                    }
                }
            }

            System.err.println("PrefixLength(CIDR)를 찾지 못했습니다.");
            return null;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    private static NetworkInfo detectLinux() {

        NetworkInfo info = new NetworkInfo();

        try {

            // 기본 라우팅 정보 얻기
            Process routeProc = Runtime.getRuntime().exec("ip route show");

            BufferedReader routeReader = new BufferedReader(
                    new InputStreamReader(routeProc.getInputStream())
            );

            String line;

            while ((line = routeReader.readLine()) != null) {

                // 예시:
                // default via 192.168.0.1 dev wlan0 proto dhcp metric 600
                if (line.startsWith("default")) {

                    String[] parts = line.split("\\s+");

                    for (int i = 0; i < parts.length; i++) {

                        if (parts[i].equals("via")) {
                            info.gateway = parts[i + 1];
                        }

                        if (parts[i].equals("dev")) {
                            info.interfaceName = parts[i + 1];
                        }
                    }
                }
            }

            //=========================
            // 2) 인터페이스 IP와 서브넷(CIDR) 얻기
            //=========================

            if (info.interfaceName != null) {

                Process ipProc = Runtime.getRuntime().exec(
                        "ip -o -f inet addr show " + info.interfaceName
                );

                BufferedReader ipReader = new BufferedReader(
                        new InputStreamReader(ipProc.getInputStream())
                );

                while ((line = ipReader.readLine()) != null) {

                    // 예시: 3: wlan0 inet 192.168.0.10/24 brd 192.168.0.255 scope global dynamic wlan0
                    if (line.contains("inet")) {
                        String[] parts = line.split("\\s+");

                        for (String p : parts) {
                            if (p.contains("/")) {

                                String[] ipParts = p.split("/");
                                info.ip = ipParts[0];         // IP 주소
                                int cidr = Integer.parseInt(ipParts[1]);  // 24

                                info.subnetMask = cidrToMask(cidr);       // 255.255.255.0
                            }
                        }
                    }
                }

            }

            return info;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }


    private static String cidrToMask(int cidr) {

        int mask = 0xffffffff << (32 - cidr);

        return String.format("%d.%d.%d.%d",
                (mask >>> 24) & 0xff,
                (mask >>> 16) & 0xff,
                (mask >>> 8) & 0xff,
                mask & 0xff
        );
    }
}
