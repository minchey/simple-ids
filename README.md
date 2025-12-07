🧩 운영체제별 네트워크 인터페이스 자동 감지 방식

본 프로젝트에서는 IDS(침입 탐지 시스템)의 패킷 캡처 기능을 수행하기 위해
시스템이 현재 인터넷 통신에 사용 중인 기본 네트워크 인터페이스(NIC) 를 자동으로 감지하는 기능을 구현하였습니다.
운영체제별 NIC 구조가 서로 다르기 때문에, macOS와 Windows 환경에서 각각 적절한 방식을 사용하였습니다.

🖥️ macOS에서의 인터페이스 감지 방식

macOS에서는 다음 명령어를 통해 기본 라우팅 경로(default route)를 확인할 수 있습니다.
route -n get default

이 명령의 결과에는 다음과 같은 정보가 포함됩니다.
interface: en0
gateway: 192.168.0.1

본 프로젝트에서는 여기서 제공되는 interface: 값을 사용하여
macOS의 기본 네트워크 인터페이스를 식별하였습니다.

✔ macOS 방식의 장점

운영체제의 라우팅 테이블을 기반으로 직접 인터페이스를 조회하기 때문에 정확도가 높습니다.

macOS의 Wi-Fi(en0), 유선(en1) 등의 인터페이스를 별도의 변환 과정 없이 바로 사용 가능합니다.

한글/지역 설정 등 문자 인코딩의 영향을 받지 않습니다.

즉, macOS에서는 OS가 제공하는 기본 라우팅 정보를 직접 활용하는 방식으로
안정적인 NIC 자동 감지를 구현하였습니다.

🪟 Windows에서의 인터페이스 감지 방식

Windows는 macOS와 달리 다음과 같은 이유로 기본 NIC을 직접 문자열로 얻기 어렵습니다.

❗ 1. Windows의 인터페이스 별칭(Alias)은 한글일 수 있습니다

예:

이더넷

Wi-Fi

로컬 영역 연결

이러한 Alias는 사용자 언어에 따라 달라지며,
네트워크 패킷 캡처 라이브러리인 pcap4j에서는 이 이름을 사용할 수 없습니다.

pcap4j는 다음과 같은 시스템 내부 장치명(Device Name) 을 사용합니다.

\Device\NPF_{AF4CDFBA-0345-47A5-B5F9-01B681E63D3E}

이 값은 Windows PowerShell의 Alias와 직접적인 연관이 없기 때문에
Alias 기반으로 NIC을 찾는 방식은 사용할 수 없었습니다.

❗ 2. Windows PowerShell의 출력 인코딩 문제(CP949/UTF-8)

PowerShell은 기본적으로 CP949(ANSI)로 출력하고,
자바는 UTF-8로 입력을 읽기 때문에
Alias가 한글인 경우 다음과 같이 깨지는 문제가 발생했습니다.
이더넷 → ?????
따라서 Alias를 활용한 방식은 신뢰할 수 없었습니다.

pcap4j는 다음과 같이 장치의 실제 하드웨어 설명을 기반으로 NIC을 구분합니다.

예:
Realtek PCIe GbE Family Controller
Intel(R) Wireless-AC 9560


따라서 Windows에서는 Alias 대신
InterfaceDescription을 사용하여 NIC을 확인하는 방식이 적합합니다.

⭐ Windows에서 채택한 최종 해결 방식

본 프로젝트에서는 Windows에서 다음 명령어를 사용하여
“기본 게이트웨이가 존재하는 인터페이스”를 선택하였습니다.

Get-NetIPConfiguration |
Where-Object {$_.IPv4DefaultGateway -ne $null} |
Select-Object -ExpandProperty InterfaceDescription


이 명령은 실제 인터넷 통신에 사용되는 NIC의
InterfaceDescription 값을 정확하게 반환합니다.

예:

Realtek PCIe GbE Family Controller


그 후, pcap4j가 제공하는 장치 목록에서
description이 동일한 인터페이스를 자동으로 매칭하여
Windows에서도 올바른 NIC을 감지하도록 구현하였습니다.

🧩 Windows 방식의 장점

한글 Alias 문제를 완전히 제거하였습니다.

인코딩(CP949/UTF-8) 문제의 영향을 받지 않습니다.

pcap4j와 동일한 기준(InterfaceDescription)으로 매칭하여 정확성이 높습니다.

실제 기본 게이트웨이를 기반으로 하므로,
현재 인터넷 통신에 사용되는 인터페이스만 선택됩니다.

