🧩 운영체제별 네트워크 인터페이스 자동 감지 방식

본 프로젝트에서는 IDS(침입 탐지 시스템)의 패킷 캡처 기능을 수행하기 위해,
현재 시스템이 인터넷 통신에 사용 중인 기본 네트워크 인터페이스(NIC) 를 자동으로 감지하는 기능을 구현하였습니다.

운영체제별 NIC 구조가 서로 다르기 때문에 macOS와 Windows에서는 각각 다른 접근 방식을 사용하였습니다.

🖥️ macOS에서의 인터페이스 감지 방식

macOS에서는 다음 명령어를 통해 기본 라우팅 경로(default route)를 확인할 수 있습니다.

route -n get default


이 명령의 출력에는 다음과 같은 정보가 포함됩니다.

interface: en0
gateway: 192.168.0.1


본 프로젝트에서는 interface: 값(en0 등)을 기반으로
현재 macOS가 실제로 사용 중인 네트워크 인터페이스를 식별하였습니다.

✔ macOS 방식의 장점

운영체제가 제공하는 라우팅 테이블 정보를 기반으로 직접 조회하기 때문에 정확도가 매우 높습니다.

Wi-Fi(en0), 유선(en1) 등의 인터페이스를 추가적인 변환 없이 바로 사용할 수 있습니다.

한글/지역 설정 등 문자 인코딩의 영향을 받지 않습니다.

➡️ macOS에서는 OS의 기본 라우팅 정보를 직접 활용하는 방식으로 안정적인 NIC 감지를 구현하였습니다.

🪟 Windows에서의 인터페이스 감지 방식

Windows는 macOS와 달리 “기본 NIC 이름”을 문자열로 직접 얻기 어렵습니다.
그 이유는 다음과 같습니다.

❗ 1. Windows의 NIC 별칭(Alias)은 한글일 수 있습니다

예:

이더넷

Wi-Fi

로컬 영역 연결

이러한 별칭(Alias)은 PC 언어 설정에 따라 달라지며,
패킷 캡처 라이브러리인 pcap4j에서는 이를 사용할 수 없습니다.

pcap4j는 다음과 같은 시스템 내부 장치명(Device Name) 을 사용합니다.

\Device\NPF_{AF4CDFBA-0345-47A5-B5F9-01B681E63D3E}


이 값은 PowerShell Alias와 전혀 연관이 없기 때문에
Alias 기반으로 NIC을 찾는 방식은 사용할 수 없었습니다.

❗ 2. PowerShell 출력 인코딩 문제(CP949 ↔ UTF-8)

Windows PowerShell은 기본적으로 CP949(ANSI) 로 출력하고,
Java는 UTF-8로 입력을 읽습니다.

따라서 Alias가 한글일 경우 다음과 같이 깨짐 현상이 발생합니다.

이더넷 → ?????


이로 인해 Alias 기반 감지는 신뢰성이 떨어졌습니다.

❗ 3. pcap4j는 InterfaceDescription 기반으로 NIC을 구분합니다

예:

Realtek PCIe GbE Family Controller

Intel(R) Wireless-AC 9560

즉, Windows에서는 InterfaceDescription을 기준으로 pcap4j와 매칭하는 방식이 더 적합합니다.

⭐ Windows에서 채택한 최종 해결 방식

본 프로젝트에서는 다음 PowerShell 명령을 사용하여
“기본 게이트웨이를 보유한 인터페이스”를 탐지하였습니다.

Get-NetIPConfiguration |
Where-Object {$_.IPv4DefaultGateway -ne $null} |
Select-Object -ExpandProperty InterfaceDescription


출력 예:

Realtek PCIe GbE Family Controller


이 값을 바탕으로 pcap4j에서 제공하는 NIC 목록을 순회하며
description 이 일치하는 인터페이스를 찾아 최종적으로 선택하였습니다.

🧩 Windows 방식의 장점

한글 Alias 문제를 완전히 제거하였습니다.

출력 인코딩 문제(CP949/UTF-8)의 영향을 받지 않습니다.

pcap4j와 동일한 기준(InterfaceDescription) 을 사용하므로 매칭 정확도가 높습니다.

실제 기본 게이트웨이를 통해 인터넷 통신 중인 인터페이스만 선택하게 됩니다.