# Simple IDS — ARP Spoofing Detection Tool

### 🔒 Lightweight ARP-based Intrusion Detection System
Windows 환경에서 실시간 ARP 스푸핑 공격을 탐지하는 IDS 도구입니다.  
jlink로 경량 JRE를 포함하고 있어 **Java 미설치 환경에서도 바로 실행할 수 있습니다.**

---

## 🚀 실행 방법

### 1) Npcap 설치 (필수)
패킷 캡처를 위해 **Npcap**이 필요합니다.  
https://npcap.com

설치 옵션
- ✔ WinPcap API-Compatible Mode 체크

---

### 2) 프로젝트 다운로드 후 압축 해제
GitHub Releases의 `simple-ids.zip` 다운로드 → 압축 해제

---

### 3) 실행
압축을 해제한 폴더에서:

run.bat

더블 클릭하면 실행됩니다.

Java 설치 필요 없음 (`runtime/` 폴더에 포함).

---

## 📡 기능 개요

### ✔ 1) ARP 패킷 실시간 캡처
LAN 내부에서 발생하는 모든 ARP 요청/응답 패킷을 모니터링합니다.

### ✔ 2) IP → MAC 매핑 테이블 유지
정상적인 ARP 테이블을 지속적으로 학습하여 관리합니다.

### ✔ 3) MAC 변조 감지  
동일 IP에서 MAC 주소가 바뀐 경우
→ ARP Spoofing 가능성 경고

### ✔ 4) Gateway Spoofing 탐지
게이트웨이가 아닌 장비가 “나는 게이트웨이다”라고 주장할 경우 자동 감지합니다.

---

## 🧪 로그 출력 예시

📡 게이트웨이에 ARP Request 전송 완료
[+] ARP 기반 IDS 감지 시작...

========== ARP 탐지 (LAN 내) ==========\
종류(Operation) → REQUEST\
보낸 IP → 192.168.0.15\
보낸 MAC → 70:30:5d:83:5f:31\
대상 IP → 192.168.0.1\
대상 MAC → 00:00:00:00:00:00

🚨 [경고] 동일 IP에서 MAC 변경 감지!\
IP: 192.168.0.15\
기존 MAC: 70:30:5d:83:5f:31\
새 MAC: 11:22:33:44:55:66

🚨🚨 [심각] 게이트웨이 ARP 스푸핑 감지!\
정상 MAC: 40:44:cc:5a:c6:c7\
스푸핑 MAC: 11:22:33:44:55:66


---

## 📁 패키지 구조

simple-ids/\
├── build/libs/simple-ids.jar # IDS 프로그램 JAR\
├── runtime/ # jlink로 생성한 최소 JRE (Java 설치 불필요)\
├── run.bat # 실행 스크립트\
├── README.md # 설명서\
├── src/ # Java 소스 코드


---

## 🛠 기술 스택

- Java 17
- Pcap4j
- jlink (커스텀 런타임 이미지 생성)
- Windows / Npcap 환경 최적화

---

## 📌 개발 목적
ARP 스푸핑은 LAN 환경에서 가장 흔하고 위험한 공격 중 하나입니다.  
이 IDS는 다음을 목표로 개발되었습니다:

- 로컬 네트워크에서 스푸핑 탐지 자동화
- 실시간 경고 시스템 구축
- 최소 환경에서 실행 가능한 보안 도구 제작

---

## 📬 문의 / 개발자
Developed by **Minchey**  
GitHub: https://github.com/minchey

