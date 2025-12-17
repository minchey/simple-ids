# 🛡 Simple IDS (ARP Spoofing Detection System)

Java + Pcap4J 기반의 **LAN 내부 ARP 스푸핑 탐지 IDS**입니다.  
Gateway MAC 위조 탐지, IP–MAC 매핑 분석, LAN 범위 필터링 등을 지원합니다.

Windows + macOS 모두 실행 가능한 독립 실행 패키지를 제공합니다.

---

# 📌 기능 소개

### ✔ 실시간 ARP 패킷 캡처
프라미스큐어스 모드로 네트워크의 ARP 패킷을 실시간 수신합니다.

### ✔ 게이트웨이 ARP 스푸핑 탐지
게이트웨이 IP가 인증되지 않은 MAC 주소를 사용하면 즉시 경고합니다.

### ✔ IP → MAC / MAC → IP 테이블 기반 스푸핑 감지
동일 IP가 서로 다른 MAC으로 변경되면 경고합니다.  
동일 MAC이 서로 다른 IP로 변경되어도 경고합니다.

### ✔ LAN 범위 필터링
서브넷 마스크 기반으로 **내 LAN 내부의 패킷만** 분석합니다.

---

# 📦 실행 파일 구성

simple-ids/\
├── simple-ids.jar\
├── runtime-win/ (Windows 실행용 JRE)\
├── runtime-mac/ (macOS 실행용 JRE)\
├── run.bat (Windows 실행 스크립트)\
├── run.sh (macOS 실행 스크립트)\
└── README.md


---

# 🪟 Windows 실행 방법

### ✔ 1) Npcap 설치 필수
ARP 패킷 캡처를 위해 반드시 Npcap 설치 필요  
https://npcap.com/

설치 옵션:
- ✔ "Install Npcap in WinPcap API-compatible Mode" 체크

---

### ✔ 2) IDS 실행

압축 해제 →  
run.bat\
더블클릭 또는 CMD에서 실행.

---

# 🍎 macOS 실행 방법

macOS는 BPF 장치 접근 때문에 **root 권한 필요**.

### ✔ 1) 실행 권한 부여

chmod +x run.sh

### ✔ 2) root 권한으로 실행

sudo ./run.sh


---

# ⚠️ macOS 경고 관련

다음 경고는 정상이며 무시해도 됨:

WARNING: Restricted methods will be blocked...
Use --enable-native-access=ALL-UNNAMED

---

# 📊 실행 예시

### 게이트웨이 정상 응답

📡 게이트웨이에 ARP Request 전송 완료\
📌 게이트웨이 MAC 학습됨 → 88:3c:1c:71:25


### LAN 패킷 출력

=== ARP 탐지 (LAN) ===\
Sender IP = 172.30.1.254\
Sender MAC = 88:3c:1c:1c:71:25\
Target IP = 172.30.1.65


### 스푸핑 감지

🚨🚨 [심각] 게이트웨이 ARP 스푸핑 감지!\
정상 MAC: 88:3c:1c:1c:71:25\
공격 MAC: 66:77:88:99:AA:BB


---

# 🛠 개발자 정보 (빌드)

### fatJar 생성
./gradlew fatJar

### Windows용 JRE 생성
jlink --no-header-files --no-man-pages --strip-debug
--compress=2
--add-modules java.base,java.logging,java.net.http,java.xml,java.sql
--output runtime-win


### macOS용 JRE 생성
jlink --no-header-files --no-man-pages --strip-debug
--compress=2
--add-modules java.base,java.logging,java.net.http,java.xml,java.sql
--output runtime-mac


---

# 📩 Contact

Developer: **minchey**  
GitHub: https://github.com/minchey  
Security-focused Java developer.

---

# 📝 License
MIT License
