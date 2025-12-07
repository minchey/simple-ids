import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;


public class App {
    public static void main(String[] args) throws PcapNativeException{


        // 1) OS에 맞게 기본 NIC 자동 감지
        String defaultIf = detectDefaultInterface();
        System.out.println("자동 선택 된 NIC = " + defaultIf);

        // 2) pcap4j로 NIC 객체 가져오기
        PcapNetworkInterface nif = Pcaps.getDevByName(defaultIf);
        if(nif == null){
            System.err.println("NIC를 찾지 못했습니다: " + defaultIf);
            return;
        }
    }

    private static String detectDefaultInterface(){
        String os = System.getProperty("os.name").toLowerCase();

        if(os.contains("mac")){
            return getDefaultInterfaceMac();
        } else if (os.contains("win")) {
            return getDefaultInterfaceWin();
        } else if (os.contains("linux")) {
            return getDefaultInterfaceLinux();
        }
        return null; //감지실패
    }

    private static String getDefaultInterfaceMac(){
        try {
            //mac os 기본 라우팅 정보를 조회하는 명령어 실행
            Process proc = Runtime.getRuntime().exec("route -n get default");

            // 명령어의 출력 결과를 한 줄씩 읽기 위한 Reader 구성
            BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null){
                // interface: en0 같은 줄 찾기
                if(line.trim().startsWith("interface:")){
                    return line.split(":")[1].trim();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null; // 실패 시 null 반환
    }

    private static String getDefaultInterfaceWin() {
        try {
            // 1) 모든 네트워크 인터페이스 + 기본 게이트웨이 정보 가져오기
            Process proc = Runtime.getRuntime().exec(new String[] {
                    "powershell.exe", "-NoLogo", "-Command",
                    "chcp 65001 > $null; " +
                            "(Get-NetIPConfiguration | " +
                            "Where-Object {$_.IPv4DefaultGateway -ne $null} | " +
                            "Select-Object -ExpandProperty InterfaceDescription)"
            });

            BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream(), "UTF-8"));
            String adapterDesc = reader.readLine();

            if (adapterDesc == null || adapterDesc.trim().isEmpty()) {
                System.err.println("기본 게이트웨이를 가진 NIC을 찾지 못했습니다.");
                return null;
            }

            adapterDesc = adapterDesc.trim();
            System.out.println("Windows Adapter Description = " + adapterDesc);

            // 2) pcap4j 목록에서 description 매칭
            for (PcapNetworkInterface dev : Pcaps.findAllDevs()) {
                if (dev.getDescription() != null && dev.getDescription().contains(adapterDesc)) {
                    return dev.getName();  // pcap4j NIC name 반환
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }




    private static String getDefaultInterfaceLinux(){
        try{
            Process proc = Runtime.getRuntime().exec("ip route show");
            BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));

            String line;
            while ((line = reader.readLine())!= null){
                if(line.startsWith("default")){
                    // 예: default via 192.168.0.1 dev wlan0
                    String[] parts = line.split("\\s+");
                    for(int i = 0; i < parts.length; i++){
                        if(parts[i].equals("dev")){
                            return parts[i +1];
                        }
                    }
                }
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
}
