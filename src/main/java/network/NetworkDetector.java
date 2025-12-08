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

    private static NetworkInfo detectMac(){
        NetworkInfo info = new NetworkInfo();

        try {
            // macOS 기본 라우팅 테이블 읽기
            Process proc = Runtime.getRuntime().exec("route -n get default");
            BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null){

                //인터페이스 명 찾기
                if(line.trim().startsWith("interface:")){
                    info.interfaceName = line.split(":")[1].trim();
                }

                //기본 게이트웨이 찾기
                if(line.trim().startsWith("gateway:")){
                    info.gateway = line.split(":")[1].trim();
                }

                //내 ip주소 찾기
                if(line.trim().startsWith("inet:")){
                    info.ip = line.split(":")[1].trim();
                }

                // 서브넷 마스크 찾기
                if (line.trim().startsWith("netmask:")) {
                    String hexMask = line.split(":")[1].trim();
                    info.subnetMask = convertHexMaskToDecimal(hexMask);
                }
            }

            return info;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
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

            Process proc = Runtime.getRuntime().exec(new String[]{
                    "powershell.exe", "-NoLogo", "-Command",
                    "chcp 65001 > $null; " +
                            "(Get-NetIPConfiguration | " +
                            " Where-Object {$_.IPv4DefaultGateway -ne $null}) | " +
                            "Select-Object InterfaceDescription, IPv4Address, IPv4DefaultGateway, IPv4SubnetMask"
            });

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(proc.getInputStream(), "UTF-8")
            );

            String line;
            while ((line = reader.readLine()) != null) {

                line = line.trim();
                if (line.isEmpty()) continue;

                if (line.startsWith("InterfaceDescription")) {
                    info.interfaceName = line.replace("InterfaceDescription : ", "").trim();
                }
                else if (line.startsWith("IPv4Address")) {
                    info.ip = line.replace("IPv4Address : ", "").trim();
                }
                else if (line.startsWith("IPv4SubnetMask")) {
                    info.subnetMask = line.replace("IPv4SubnetMask : ", "").trim();
                }
                else if (line.startsWith("IPv4DefaultGateway")) {
                    info.gateway = line.replace("IPv4DefaultGateway : ", "").trim();
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        return info;
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
