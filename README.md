
# 🛡️ Simple IDS (ARP 기반 침입 탐지 시스템)

본 프로젝트는 **로컬 네트워크(LAN)에서 발생하는 ARP 패킷을 실시간으로 감시하고,  
ARP 스푸핑(ARP Spoofing) 공격을 탐지하는 IDS**입니다.

운영체제별로 실제 네트워크 인터페이스 정보를 자동으로 감지하고,  
패킷 캡처 라이브러리인 **pcap4j**를 사용해 ARP 트래픽을 분석합니다.

---

# 📌 주요 기능

### ✅ 1. 운영체제(OS)별 NIC 자동 감지

운영체제마다 네트워크 인터페이스 구조가 달라 이를 자동으로 감지해야 합니다.

| OS | 사용 방식 |
|----|-----------|
| **macOS** | `route -n get default` 명령어로 NIC/IP/MASK/GW 탐지 |
| **Windows** | `Get-NetIPConfiguration` 정보를 분석해 실제 NIC 매칭 |
| **Linux** | `ip route show`, `ip addr` 명령어 조합하여 IP/MASK/GW 추출 |

---

# 🖥️ macOS 탐지 방식

macOS는 다음 명령어로 기본 라우팅 정보를 제공함:

```
route -n get default
```

출력 예:
```
interface: en0
gateway: 192.168.0.1
inet: 192.168.0.10
netmask: 0xffffff00
```

여기서:

- **interface** → 기본 NIC (예: en0)
- **gateway** → 공유기 IP
- **inet** → 내 IP
- **netmask(hex)** → 16진 마스크 → 10진 마스크로 변환 필요

---

# 🪟 Windows 탐지 방식

Windows는 macOS와 다르게 **인터페이스 Alias가 한글일 수 있음**  
예:
- 이더넷
- Wi-Fi
- 로컬 영역 연결

또한 PowerShell 기본 인코딩이 CP949여서 UTF-8 출력이 깨짐.  
그러므로 Alias 기반 탐지 ❌  
→ **실제 하드웨어 설명(InterfaceDescription)을 기준으로 매칭해야 함**

사용 명령어:

```
Get-NetIPConfiguration
```

이 명령에서:

- InterfaceDescription
- IPv4Address
- IPv4DefaultGateway
- PrefixLength(=CIDR)

을 읽어 네트워크 정보를 완성.

그 후 pcap4j의 NIC 목록과 **description을 비교하여 정확한 NIC 선택**.

---

# 🐧 Linux 탐지 방식

Linux는 다음 데이터를 조합해야 함:

### 1) 기본 라우트

```
ip route show
```

예:
```
default via 192.168.0.1 dev wlan0
```

여기서 NIC = `wlan0`, gateway = `192.168.0.1`

### 2) IP + CIDR

```
ip -o -f inet addr show wlan0
```

예:
```
192.168.0.10/24
```

CIDR → subnet mask 변환  
예: `/24 → 255.255.255.0`

---

# 📡 ARP 기반 IDS 로직

### ✔ LAN 내부 ARP 트래픽만 분석
IP/MASK 기반 네트워크 계산으로 WAN의 ARP는 모두 제외

---

# 🔍 탐지 구조

## 1. **IP → MAC 테이블**
동일한 IP에서 다른 MAC이 나오면:

```
🚨 동일 IP에서 MAC 변경 감지!
→ ARP 스푸핑 가능성
```

## 2. **MAC → IP 테이블**
동일 MAC이 여러 IP로 나타나면:

```
⚠ 동일 MAC에서 여러 IP 사용 감지 → DHCP 스푸핑 가능성
```

## 3. **게이트웨이 스푸핑 탐지**
게이트웨이와 동일한 IP를 쓰는 패킷이 들어오면:

- 최초 MAC 저장
- 다음번에 MAC이 다르면 공격으로 판단

```
🚨🚨 게이트웨이 ARP 스푸핑 감지!
```

---

# 📡 게이트웨이 MAC 확인을 위한 ARP Request

IDS는 필요 시 게이트웨이에게 ARP Request를 직접 보냄:

- 브로드캐스트 MAC: `ff:ff:ff:ff:ff:ff`
- 목적지 MAC: `00:00:00:00:00:00`
- 목적지 IP: 게이트웨이 IP

이를 통해 **정상 게이트웨이 MAC을 정확히 기록**하여 공격 감지.

---

# ❌ 이 프로젝트는 Docker로 실행할 수 없음

### 이유는 다음과 같음:

1. 도커는 **가상의 NIC**만 제공
2. 호스트 컴퓨터의 실제 NIC 패킷을 받을 수 없음
3. ARP 트래픽은 로컬 브로드캐스트 기반이므로  
   도커 내부에서는 **LAN 패킷을 절대 볼 수 없음**

따라서 IDS는 **반드시 로컬 OS에서 직접 실행해야 함**

---

# ✔ 실행 방법

### 1) 빌드 후 JAR 실행

```
java -jar simple-ids.jar
```

### 2) Windows EXE 패키징 가능
요청 시 Inno Setup / Launch4j 버전도 제공 가능.

---

# 📦 프로젝트 구조

```
simple-ids/
 ├── App.java                # 메인 IDS 실행부 (패킷 감지)
 ├── network/
 │    ├── NetworkDetector.java  # OS별 NIC/IP/MASK 탐지
 │    ├── NetworkInfo.java      # 네트워크 정보 저장 DTO
 │    ├── NetworkCalc.java      # 서브넷 계산 util
 ├── README.md
 └── build.gradle
```

---

# ✨ 마무리

이 프로젝트는 단순히 ARP를 출력하는 수준이 아니라,

✔ OS별 NIC 탐지  
✔ 실시간 패킷 캡처  
✔ IP/MAC 일관성 검증  
✔ 게이트웨이 스푸핑 감지  
✔ ARP Request 전송


---