# 운영체제별 네트워크 인터페이스 자동 감지 방식

본 프로젝트에서는 IDS(침입 탐지 시스템)의 패킷 캡처 기능을 수행하기 위해  
현재 시스템이 인터넷 통신에 사용 중인 **기본 네트워크 인터페이스(NIC)** 를 자동으로 감지하는 기능을 구현하였습니다.  
운영체제별 NIC 구조가 서로 다르기 때문에 macOS와 Windows 환경에서 각각 적절한 방식을 사용하였습니다.

---

## 1. macOS에서의 인터페이스 감지 방식

macOS에서는 다음 명령어를 통해 기본 라우팅 경로(default route)를 확인할 수 있습니다.

```bash
route -n get default
```

예시 출력:

```
interface: en0
gateway: 192.168.0.1
```

본 프로젝트는 이 중 `interface:` 값(en0 등)을 기반으로  
현재 macOS가 실제로 사용 중인 네트워크 인터페이스를 식별하였습니다.

### macOS 방식의 장점

- 운영체제의 라우팅 테이블을 기반으로 직접 조회하기 때문에 정확도가 높습니다.
- Wi-Fi(en0), 유선(en1) 등의 인터페이스를 추가적인 변환 없이 바로 사용할 수 있습니다.
- 한글/지역 설정 등 문자 인코딩의 영향을 받지 않습니다.

---

## 2. Windows에서의 인터페이스 감지 방식

Windows는 macOS와 달리 기본 NIC 이름을 단순 문자열로 얻기 어렵습니다.

### (1) NIC 별칭(Alias)이 한글일 수 있음

예시:

- 이더넷
- Wi-Fi
- 로컬 영역 연결

하지만 pcap4j는 다음과 같은 **시스템 내부 장치명(Device Name)** 을 사용합니다.

```
\Device\NPF_{AF4CDFBA-0345-47A5-B5F9-01B681E63D3E}
```

Alias(이더넷 등)와 내부 장치명은 서로 연결되어 있지 않기 때문에  
Alias 기반 감지는 사용할 수 없었습니다.

---

### (2) PowerShell 출력 인코딩 문제(CP949 → UTF-8)

- PowerShell 기본 출력: CP949(ANSI)
- Java 입력: UTF-8

따라서 NIC Alias가 한글일 경우:

```
이더넷 → ????? 
```

이와 같이 깨지는 문제가 발생하여 신뢰성이 떨어집니다.

---

### (3) pcap4j는 InterfaceDescription 기반으로 NIC을 구분함

예시:

- Realtek PCIe GbE Family Controller
- Intel(R) Wireless-AC 9560

따라서 Windows에서는 Alias가 아니라  
**InterfaceDescription을 기준으로 매칭하는 방식이 더 적합합니다.**

---

## Windows에서 사용한 최종 감지 방식

Windows에서는 기본 게이트웨이가 존재하는 네트워크 인터페이스를 조회하여  
그 인터페이스의 **InterfaceDescription** 을 가져오는 방식을 사용하였습니다.

```powershell
Get-NetIPConfiguration |
    Where-Object {$_.IPv4DefaultGateway -ne $null} |
    Select-Object -ExpandProperty InterfaceDescription
```

출력 예:

```
Realtek PCIe GbE Family Controller
```

이 값을 기반으로 pcap4j에서 제공하는 NIC 목록의  
`description` 값과 매칭하여 실제 네트워크 인터페이스를 선택하였습니다.

---

## Windows 방식의 장점

- 한글 Alias 문제를 완전히 제거하였습니다.
- 인코딩(CP949/UTF-8) 문제의 영향을 받지 않습니다.
- pcap4j와 동일한 기준(InterfaceDescription)을 사용하여 정확성이 높습니다.
- 실제 기본 게이트웨이를 기반으로 하므로, 인터넷 통신에 사용되는 인터페이스만 선택됩니다.

---

## 운영체제별 감지 방식 요약

| 운영체제 | 감지 방식 | 특징 |
|----------|-----------|--------|
| macOS | `route -n get default` → interface 값 사용 | 라우팅 테이블 기반, 인코딩 영향 없음 |
| Windows | 기본 게이트웨이 보유 NIC → InterfaceDescription 매칭 | 한글 Alias 문제 해결, pcap4j와 동일 기준 사용 |

