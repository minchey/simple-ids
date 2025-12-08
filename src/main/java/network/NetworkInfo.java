package network;

/**
 * 내 컴퓨터의 네트워크 정보를 담아두는 박스 역할
 */
public class NetworkInfo {

    // 내 IP 주소 (예: 192.168.0.10)
    public String ip;

    // 서브넷 마스크 (예: 255.255.255.0)
    public String subnetMask;

    // 기본 게이트웨이 주소 (예: 192.168.0.1)
    public String gateway;

    // 내가 사용하는 인터페이스 이름 (예: en0, eth0, \Device\NPF_XXXX)
    public String interfaceName;

}
