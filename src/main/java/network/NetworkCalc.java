package network;

public class NetworkCalc {

    // 문자열 IP → 32비트 정수 변환
    public static long ipToLong(String ip) {
        String[] parts = ip.split("\\.");
        long p1 = Long.parseLong(parts[0]);
        long p2 = Long.parseLong(parts[1]);
        long p3 = Long.parseLong(parts[2]);
        long p4 = Long.parseLong(parts[3]);

        return (p1 << 24) | (p2 << 16) | (p3 << 8) | p4;
    }

    // 서브넷 마스크 문자열 → 32비트 정수
    public static long maskToLong(String mask) {
        return ipToLong(mask);
    }

    // LAN 비교 (true = 같은 LAN)
    public static boolean isSameNetwork(String myIp, String targetIp, String mask) {
        long my = ipToLong(myIp);
        long target = ipToLong(targetIp);
        long m = maskToLong(mask);

        return (my & m) == (target & m);
    }
}
