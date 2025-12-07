import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.io.BufferedReader;
import java.io.InputStreamReader;


public class App {
    public static void main(String[] args) throws PcapNativeException{
        // 1) 모든 네트워크 인터페이스 목록 가져오기
        var interfaces = Pcaps.findAllDevs();

        String defaultIf = detectDefaultInterface();
        System.out.println("자동 선택 된 NIC = " + defaultIf);

        // 2) 네트워크 인터페이스 출력
        for(var nif : interfaces){
            System.out.println("- " + nif.getName() + " : " + nif.getDescription());
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
}
