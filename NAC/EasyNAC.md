# EasyNAC – Phân Tích Kỹ Thuật Chuyên Sâu: Kiến Trúc, Cơ Chế & Flow Hoạt Động

---

## Mục Lục

1. [Tổng quan & Định vị sản phẩm](#1-tổng-quan--định-vị-sản-phẩm)
2. [Kiến trúc hệ thống](#2-kiến-trúc-hệ-thống)
3. [Kỹ thuật cốt lõi: ARP Enforcement](#3-kỹ-thuật-cốt-lõi-arp-enforcement)
4. [Flow hoạt động đầy đủ (End-to-End)](#4-flow-hoạt-động-đầy-đủ-end-to-end)
5. [Device Discovery & Profiling – Kỹ thuật nhận diện thiết bị](#5-device-discovery--profiling--kỹ-thuật-nhận-diện-thiết-bị)
6. [Zero Trust & Role-Based Access Control (RBAC)](#6-zero-trust--role-based-access-control-rbac)
7. [Anti-Spoofing & Device Fingerprinting](#7-anti-spoofing--device-fingerprinting)
8. [Automated Threat Response](#8-automated-threat-response)
9. [Zero-Day & Malware Lateral Spread Protection](#9-zero-day--malware-lateral-spread-protection)
10. [Deception Technology – Honeypot phân tán](#10-deception-technology--honeypot-phân-tán)
11. [BYOD & Guest Access Management](#11-byod--guest-access-management)
12. [Kiến trúc triển khai: 3 phương thức kết nối](#12-kiến-trúc-triển-khai-3-phương-thức-kết-nối)
13. [Enforcer Sensors & vLinks – Mở rộng bảo vệ chi nhánh](#13-enforcer-sensors--vlinks--mở-rộng-bảo-vệ-chi-nhánh)
14. [VPN Inline Enforcement](#14-vpn-inline-enforcement)
15. [High Availability (HA)](#15-high-availability-ha)
16. [Central Visibility Manager (CVM)](#16-central-visibility-manager-cvm)
17. [Tích hợp hệ sinh thái bảo mật](#17-tích-hợp-hệ-sinh-thái-bảo-mật)
18. [Compliance Checks & Endpoint Posture Validation](#18-compliance-checks--endpoint-posture-validation)
19. [Licensing & Sizing](#19-licensing--sizing)
20. [So sánh với NAC truyền thống (802.1X)](#20-so-sánh-với-nac-truyền-thống-8021x)
21. [Điểm mạnh, giới hạn & đánh giá tổng quan](#21-điểm-mạnh-giới-hạn--đánh-giá-tổng-quan)

---

## 1. Tổng Quan & Định Vị Sản Phẩm

EasyNAC là giải pháp **Network Access Control (NAC) thế hệ thứ ba**, phát triển bởi InfoExpress, Inc. – công ty bảo mật mạng có trụ sở tại Santa Clara, California. Sản phẩm được thiết kế để giải quyết điểm yếu cố hữu của các NAC truyền thống: **quá phức tạp, tốn thời gian, và đắt để triển khai**.

NAC (Network Access Control) về bản chất là tập hợp các cơ chế để:
- Kiểm soát **ai** và **thiết bị nào** được kết nối vào mạng nội bộ
- Đảm bảo thiết bị đáp ứng **chính sách bảo mật** trước khi được cấp quyền truy cập
- Phân quyền truy cập theo **vai trò và mức độ tin cậy**

Các NAC thế hệ cũ (như Cisco ISE, ForeScout) thường yêu cầu triển khai **802.1X** trên toàn bộ switch, cấu hình RADIUS server, thiết kế lại VLAN, và thường mất nhiều tháng để đưa vào vận hành. EasyNAC đặt cược vào một hướng tiếp cận khác: **không cần thay đổi hạ tầng mạng, không cần agent bắt buộc, triển khai trong vài ngày đến vài tuần**.

### Triết lý thiết kế cốt lõi

EasyNAC xây dựng trên ba nguyên tắc:

1. **Network-agnostic**: Hoạt động với bất kỳ switch, hub, AP, VPN concentrator nào – kể cả thiết bị không được quản lý (unmanaged). Không yêu cầu switch hỗ trợ 802.1X hay RADIUS.

2. **Agentless-first**: Tất cả tính năng cốt lõi (phát hiện thiết bị, phân loại, kiểm soát truy cập) hoạt động mà không cần cài agent lên endpoint. Agent là tùy chọn nâng cao, không bắt buộc.

3. **Out-of-band enforcement**: EasyNAC không nằm trên đường truyền dữ liệu chính (inline với lưu lượng thông thường). Nó can thiệp **có chọn lọc** bằng cơ chế ARP – chỉ redirect lưu lượng của các thiết bị cần kiểm soát.

---

## 2. Kiến Trúc Hệ Thống

Hệ thống EasyNAC gồm **4 thành phần chính**:

### 2.1 EasyNAC Appliance (CGX Access)

Đây là trái tim của giải pháp. Appliance có thể là:
- **Hardware appliance**: Thiết bị vật lý cứng hóa, rack-mounted
- **Virtual appliance**: Chạy trên VMware ESXi, Microsoft Hyper-V, hoặc KVM

Một Appliance có thể bảo vệ **lên đến 200 subnet/VLAN** đồng thời thông qua trunk port 802.1q. Nó cần **kết nối Layer-2** với các subnet mà nó bảo vệ – đây là điều kiện kỹ thuật bắt buộc duy nhất.

Appliance thực hiện toàn bộ vòng lặp: phát hiện → profiling → phân công quyền → thực thi (enforcement) → giám sát liên tục.

### 2.2 Enforcer Sensors (phần mềm)

Là cảm biến phần mềm nhẹ, triển khai tại các chi nhánh hoặc site từ xa. Chạy trên:
- Windows 64-bit
- Linux
- Raspberry Pi

Sensor giao tiếp ngược về Appliance trung tâm để báo cáo thiết bị phát hiện được, nhận lệnh từ Appliance và thực thi ARP enforcement cục bộ. Khi có compliance check thất bại, Sensor phát hiện trong khoảng **dưới 10 giây**.

### 2.3 vLinks (phần cứng nhỏ)

Là thiết bị phần cứng nhỏ giá thành thấp, dùng để kéo **Layer-2 tunnel** từ chi nhánh về Appliance trung tâm. Không cần cấu hình mạng – thậm chí nhân viên không chuyên IT cũng có thể lắp đặt.

### 2.4 Central Visibility Manager (CVM)

Platform quản lý tập trung dùng khi tổ chức có **nhiều Appliance** ở nhiều địa điểm. CVM không thực hiện enforcement mà chuyên về: tổng hợp báo cáo, đồng bộ policy, quản lý license phân tán, tự động backup cấu hình.

---

## 3. Kỹ Thuật Cốt Lõi: ARP Enforcement

Đây là kỹ thuật phân biệt EasyNAC với các NAC khác. Để hiểu sâu, cần nắm rõ cơ bản về ARP.

### 3.1 ARP là gì và tại sao có thể bị khai thác?

**ARP (Address Resolution Protocol)** là giao thức Layer-2 trong TCP/IP, dùng để ánh xạ địa chỉ IP thành địa chỉ MAC. Khi thiết bị A muốn gửi gói tin đến IP của thiết bị B trong cùng subnet, nó broadcast một ARP Request: *"Ai có IP x.x.x.x thì cho tôi biết MAC của bạn?"* Thiết bị B trả lời bằng ARP Reply với MAC của mình. Thiết bị A lưu thông tin này vào ARP cache.

Điểm yếu cố hữu: **ARP không có xác thực**. Bất kỳ thiết bị nào cũng có thể gửi ARP Reply giả mạo, khiến nạn nhân lưu ARP cache sai. Đây là cơ sở của cuộc tấn công ARP Spoofing / ARP Poisoning.

EasyNAC khai thác chính cơ chế này **để kiểm soát truy cập mạng**.

### 3.2 Cơ chế ARP Enforcement hoạt động ra sao

Khi EasyNAC phát hiện thiết bị không được tin cậy (untrusted), nó thực hiện:

**Bước 1 – Gửi ARP Reply định kỳ**: Appliance gửi các gói **ARP REPLY** đến thiết bị chưa được tin cậy, "thông báo" rằng gateway (hoặc các đích muốn liên lạc) có MAC address là MAC của Appliance. Kết quả: ARP cache của thiết bị bị redirect – mọi traffic ra ngoài sẽ đi qua Appliance.

**Bước 2 – Gửi ARP Reply ngược**: Song song đó, Appliance cũng gửi ARP Reply đến **các thiết bị khác** trong subnet, thông báo rằng IP của thiết bị bị restricted có MAC là MAC giả. Kết quả: các thiết bị khác trong mạng cũng không thể liên lạc trực tiếp với thiết bị bị kiểm soát.

**Bước 3 – Traffic Diversion qua ACL**: Lưu lượng của thiết bị bị redirect qua Appliance. Tại đây, một **Access Control List (ACL)** định nghĩa chính xác những gì được phép:
- Thiết bị guest: chỉ được ra internet (HTTP/HTTPS)
- Thiết bị BYOD: chỉ được truy cập tài nguyên được phê duyệt
- Thiết bị bị cách ly hoàn toàn: chỉ được truy cập captive portal để remediation
- Thiết bị bị block: không được forward gói tin nào

**Quan trọng**: EasyNAC dùng **Directed ARP REPLY** (unicast), **không** dùng ARP Broadcast. Điều này đảm bảo chỉ các thiết bị không tin cậy mới bị redirect, trong khi các thiết bị đã được tin cậy vẫn sử dụng mạng bình thường **mà không bị chậm hay gián đoạn**.

### 3.3 Bypass bằng Static ARP – và tại sao không hiệu quả

Một câu hỏi tự nhiên: *liệu kẻ tấn công có thể thoát khỏi enforcement bằng cách đặt static ARP entry?* Câu trả lời là không. Khi thiết bị bị restricted cố giao tiếp với một địa chỉ, Appliance sẽ **liên tục gửi ARP cập nhật đến thiết bị đích**, đảm bảo thiết bị đích luôn có ARP cache trỏ về Appliance thay vì về thiết bị bị restricted. Thiết bị bị restricted không thể kiểm soát ARP cache của thiết bị đích.

### 3.4 So sánh với các phương pháp enforcement khác

| Phương pháp | Yêu cầu | Ưu điểm | Nhược điểm |
|---|---|---|---|
| **802.1X** | Switch hỗ trợ, RADIUS server, supplicant trên endpoint | Mạnh, chuẩn công nghiệp | Phức tạp, tốn kém |
| **VLAN-based enforcement** | Switch managed, cấu hình VLAN | Tương đối mạnh | Cần thay đổi thiết kế mạng |
| **ARP Enforcement (EasyNAC)** | Chỉ cần Layer-2 visibility | Không cần thay đổi mạng, hoạt động với mọi switch | Chỉ áp dụng trực tiếp cho IPv4; IPv6 cần phương pháp khác |
| **Inline enforcement** | Thiết bị nằm trên đường truyền | Kiểm soát tuyệt đối | Tạo single point of failure nếu không có HA |

---

## 4. Flow Hoạt Động Đầy Đủ (End-to-End)

Dưới đây là toàn bộ vòng đời xử lý từ khi thiết bị mới xuất hiện cho đến khi được cấp hoặc bị từ chối quyền truy cập.

```
┌─────────────────────────────────────────────────────────────────┐
│                  THIẾT BỊ KẾT NỐI VÀO MẠNG                      │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                    DHCP Request / ARP Broadcast
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│              PHASE 1: DETECTION (< 1 giây)                       │
│  - EasyNAC lắng nghe Layer-2 broadcast traffic                   │
│  - Phát hiện MAC address mới                                     │
│  - Ghi nhận: MAC, IP (nếu có), thời gian, VLAN                  │
│  - Ngay lập tức: đặt thiết bị vào trạng thái "UNTRUSTED"        │
│  - Bắt đầu ARP enforcement nếu enforcement mode đang bật        │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│              PHASE 2: PROFILING (song song với enforcement)      │
│                                                                  │
│  PASSIVE PROFILING:                                              │
│  - Phân tích ARP packets (MAC OUI → nhà sản xuất)               │
│  - Phân tích DHCP packets (Option 55 fingerprint → OS)          │
│  - Lắng nghe mDNS/Bonjour broadcasts                            │
│  - Theo dõi NetBIOS name announcements                           │
│                                                                  │
│  ACTIVE PROFILING (sau khi device được phát hiện):              │
│  - NMAP scanning: kiểm tra open ports, OS fingerprinting        │
│  - SNMP: query switch để lấy thông tin port, device info         │
│  - SMB/NetBIOS: lấy hostname, workgroup/domain                  │
│  - WMI (nếu Windows và có credential): OS version, patches      │
│  - LLTD (Link Layer Topology Discovery): topology info          │
│  - UPnP: thông tin thiết bị IoT                                  │
│  - Kết hợp với AD (nếu đã cấu hình): domain membership          │
│  - Kết hợp với 3rd-party AV/XDR API                             │
│                                                                  │
│  OUTPUT: Device Profile                                          │
│  {MAC, IP, Hostname, OS, Device Type, Vendor, Open Ports,       │
│   Domain Status, AV Status, Patch Status, Switch Port}          │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│              PHASE 3: ROLE ASSIGNMENT                            │
│                                                                  │
│  Áp dụng Auto Trust Policy theo thứ tự ưu tiên:                 │
│                                                                  │
│  1. Blocklist check → nếu có: RESTRICT ngay                     │
│  2. Allowlist check → nếu có: FULL ACCESS ngay                  │
│  3. Auto Trust Policy:                                           │
│     - Domain-joined? → kiểm tra với AD server                   │
│     - AV managed & up-to-date? → kiểm tra với AV server         │
│     - Patch compliant? → kiểm tra với patch management          │
│     - Device type match? → từ device profiling                  │
│     - Fingerprint match? → chống spoofing                       │
│                                                                  │
│  ROLES (ví dụ):                                                  │
│  - FULL ACCESS: thiết bị domain-joined, AV compliant            │
│  - RESTRICTED: BYOD (chỉ tài nguyên được phê duyệt)            │
│  - INTERNET ONLY: Guest                                          │
│  - QUARANTINE: bị cô lập, chỉ đến captive portal                │
│  - BLOCKED: không được phép bất kỳ traffic nào                  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│              PHASE 4: ENFORCEMENT                                │
│                                                                  │
│  Dựa trên Role được assign:                                      │
│                                                                  │
│  - FULL ACCESS: Không can thiệp, thiết bị giao tiếp bình thường │
│  - RESTRICTED/QUARANTINE:                                        │
│    * ARP Enforcement bắt đầu (directed ARP Reply)               │
│    * Traffic được redirect qua Appliance                         │
│    * ACL được áp dụng: chỉ forward packets theo policy          │
│    * DNS Redirection: DNS query redirect đến captive portal      │
│    * HTTP Redirection: HTTP traffic → captive portal page        │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│              PHASE 5: CONTINUOUS MONITORING                      │
│                                                                  │
│  - Định kỳ re-check compliance (AV status, patch, AD)           │
│  - Theo dõi hành vi bất thường (Zero-day detection)             │
│  - Lắng nghe Syslog/Email alerts từ security tools bên ngoài    │
│  - Deception monitoring (honeypot activity)                      │
│                                                                  │
│  Nếu có thay đổi (device trở nên non-compliant):               │
│  → Tự động hạ xuống role thấp hơn                               │
│  → Bắt đầu enforcement                                          │
│  → Gửi alert (Email, SMS, Teams, Slack, WhatsApp, Syslog)       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Device Discovery & Profiling – Kỹ Thuật Nhận Diện Thiết Bị

Đây là một trong những điểm kỹ thuật thú vị nhất. EasyNAC sử dụng **multi-vector profiling** kết hợp nhiều nguồn dữ liệu để xây dựng hồ sơ thiết bị càng đầy đủ càng tốt.

### 5.1 Passive Profiling – Không gửi traffic

Phương pháp này chỉ lắng nghe, không chủ động thăm dò:

- **ARP Requests**: Khi thiết bị gửi ARP, Appliance đọc được source MAC và IP. OUI (3 byte đầu của MAC) tiết lộ nhà sản xuất (ví dụ: `00:50:56` → VMware, `b8:27:eb` → Raspberry Pi Foundation).

- **DHCP Requests**: DHCP Option 55 (Parameter Request List) có thể được dùng để fingerprint hệ điều hành. Mỗi OS có "chữ ký" Option 55 khác nhau. DHCP Option 12 (Hostname) cung cấp tên máy. DHCP Option 60 (Vendor Class Identifier) cung cấp thông tin vendor.

- **NetBIOS Name Service broadcasts**: Windows machines broadcast tên computer và workgroup/domain lên mạng định kỳ.

- **mDNS/Bonjour**: Apple devices và một số IoT devices broadcast thông tin service qua Bonjour. Cho biết loại thiết bị, OS version, service đang chạy.

- **LLTD (Link Layer Topology Discovery)**: Giao thức Microsoft dùng để vẽ sơ đồ mạng. Broadcast thông tin thiết bị.

- **UPnP SSDP Announcements**: IoT devices broadcast thông tin qua UPnP/SSDP, bao gồm model, manufacturer, firmware version.

### 5.2 Active Profiling – Chủ động thăm dò

- **NMAP scanning**: Công cụ mạnh nhất để fingerprint OS và phát hiện open ports. EasyNAC tích hợp NMAP để thực hiện OS detection và service version detection. *Lưu ý: Với subnet lớn (Class B trở lên), network scanning bị tắt mặc định để tránh tạo quá nhiều traffic.*

- **SNMP**: Query các switch trong mạng để lấy thông tin về ARP table, bridge forwarding table, và interface trên switch mà thiết bị đang cắm vào (switch port location).

- **SMB/NetBIOS scans**: Kết nối đến port 137/139/445 để lấy hostname, domain, OS version.

- **WMI (Windows Management Instrumentation)**: Nếu có credential, WMI cho phép lấy thông tin chi tiết về Windows endpoint: OS version, installed patches, running processes, AV status (qua Windows Security Center).

- **RDP port check**: Kiểm tra port 3389 để xác định Windows machine.

- **AD Integration query**: Sau khi biết hostname, Appliance query trực tiếp Active Directory LDAP để xác minh device có trong domain không, thuộc OU nào, thuộc group nào.

- **3rd-party AV/XDR API**: Gọi API của CrowdStrike, SentinelOne, Sophos, etc. để kiểm tra trạng thái agent và compliance.

### 5.3 Device Profile Output

Toàn bộ thông tin được tổng hợp thành một Device Profile gồm:

| Trường | Nguồn |
|---|---|
| MAC Address | ARP/DHCP |
| IP Address | ARP/DHCP |
| Hostname | DHCP Option 12, NetBIOS, AD |
| OS & Version | NMAP, DHCP fingerprint, WMI |
| Device Type | OUI, UPnP, NMAP |
| Manufacturer/Vendor | OUI, UPnP |
| Open Ports | NMAP |
| Switch Port | SNMP |
| Domain Membership | AD integration |
| AV Status | AV API integration |
| Patch Status | Patch management integration |
| Last Seen | Continuous monitoring |
| Trust Status | Derived from all above |

---

## 6. Zero Trust & Role-Based Access Control (RBAC)

EasyNAC áp dụng mô hình **Zero Trust** theo nghĩa thực tiễn: mặc định **tất cả thiết bị đều không được tin cậy** cho đến khi được xác minh.

### 6.1 Auto Trust Policy Engine

Đây là bộ não ra quyết định. Admin định nghĩa các **rules** với điều kiện và action:

**Ví dụ các policy rule:**

```
Rule 1: Nếu [Domain Joined = True] AND [AV = Active & Up-to-date] THEN → FULL ACCESS
Rule 2: Nếu [Device Type = Printer] AND [MAC OUI = HP/Xerox/...] THEN → PRINTER ACCESS (ACL)
Rule 3: Nếu [BYOD Registration = Complete] THEN → BYOD ACCESS (ACL giới hạn)
Rule 4: Nếu [BYOD Registration = Pending] THEN → CAPTIVE PORTAL (registration page)
Rule 5: Nếu [Guest Account = Active] THEN → INTERNET ONLY
Rule 6: Nếu [AV = Outdated] THEN → RESTRICTED (chỉ AV update server)
Rule 7: Nếu [Unknown Device] THEN → QUARANTINE
```

### 6.2 Roles và ACLs

Mỗi Role được map với một **ACL** xác định traffic nào được forward:

- **FULL ACCESS**: ACL cho phép mọi traffic. ARP enforcement không kích hoạt.
- **BYOD ROLE**: ACL cho phép đến tập subnet/IP cụ thể. Chặn lateral movement đến server segment.
- **GUEST ROLE**: ACL chỉ cho phép DNS (port 53), HTTP (80), HTTPS (443) ra internet. Chặn mọi traffic internal.
- **REMEDIATION ROLE**: ACL chỉ cho phép đến captive portal IP, AV update server, patch server.
- **BLOCKED**: ACL từ chối mọi traffic.

### 6.3 Continuous Re-evaluation

Điều quan trọng: Role assignment không phải một lần. EasyNAC **liên tục kiểm tra lại** trạng thái compliance. Nếu AV của một thiết bị đang Full Access đột nhiên bị tắt → Appliance phát hiện (qua polling AV server) → tự động hạ Role → bắt đầu enforcement → gửi alert.

---

## 7. Anti-Spoofing & Device Fingerprinting

MAC Address Spoofing là một kỹ thuật tấn công cơ bản: kẻ tấn công thay đổi MAC của thiết bị mình để giả mạo một thiết bị đã được trust trong hệ thống.

### 7.1 Multi-attribute Fingerprinting

EasyNAC giải quyết vấn đề này bằng cách tạo **fingerprint đa chiều** cho mỗi thiết bị, không chỉ dựa vào MAC:

```
Fingerprint = {
  MAC Address,
  IP Address (static hay DHCP range),
  OS Type (Windows 10, Linux, iOS, etc.),
  Hostname,
  Open Ports,
  DHCP fingerprint signature,
  Switch Port (vị trí vật lý trên switch)
}
```

Khi một device mới xuất hiện với MAC trùng với thiết bị đã được trust:
1. Appliance so sánh fingerprint mới với fingerprint đã lưu
2. Nếu có sự khác biệt (ví dụ: MAC giống nhưng OS khác, hostname khác) → spoofing được phát hiện
3. Device bị giữ ở trạng thái Restricted
4. Admin được alert

**Ví dụ thực tế**: Máy in HP có fingerprint với OS="Printer firmware", hostname="HP-LaserJet-xxx". Nếu kẻ tấn công clone MAC của máy in đó, thiết bị của họ (chạy Windows/Linux) sẽ có OS fingerprint khác → bị phát hiện ngay.

### 7.2 Fingerprint-based 2FA cho VPN

Trong môi trường VPN, fingerprinting được dùng như một lớp xác thực thứ hai (2FA): *"Something you know"* (password) + *"Something you have"* (device with specific fingerprint). Mỗi agent được cài trên endpoint có một **unique serial number** – không thể giả mạo. Khi user VPN vào, EasyNAC xác minh cả credential lẫn device fingerprint.

---

## 8. Automated Threat Response

Đây là tính năng biến EasyNAC từ một công cụ kiểm soát thụ động thành một **active cyber defense platform**.

### 8.1 Nguồn trigger

EasyNAC có thể nhận trigger từ:
- **Email alerts**: Bất kỳ security tool nào gửi email cảnh báo
- **Syslog messages**: Firewall, IPS, SIEM, NDR gửi syslog event
- **API webhooks**: Từ XDR/EDR platforms
- **Internal detection**: Từ deception module, zero-day detection của chính EasyNAC

### 8.2 Cơ chế xử lý

Khi nhận trigger:
1. Parse message để extract IP/MAC của thiết bị liên quan
2. Tìm thiết bị trong Device Database
3. Thực hiện action ngay lập tức (trong vài giây):
   - Quarantine: hạ ACL xuống mức cách ly hoàn toàn
   - Restrict: giới hạn chỉ còn remediation resources
   - Block: cắt hoàn toàn
4. Ghi log sự kiện
5. Gửi notification đến admin

### 8.3 Use case điển hình

```
Kịch bản:
  CrowdStrike Falcon phát hiện ransomware trên máy PC-A (IP: 10.1.1.50)
  
Flow:
  1. CrowdStrike gửi syslog alert đến EasyNAC
  2. EasyNAC parse syslog: extract IP 10.1.1.50
  3. EasyNAC lookup Device DB: PC-A, MAC: aa:bb:cc:dd:ee:ff
  4. EasyNAC bắt đầu ARP Enforcement cho PC-A
  5. Toàn bộ traffic của PC-A bị redirect qua Appliance
  6. ACL: DROP tất cả → PC-A bị cô lập hoàn toàn trong giây lát
  7. EasyNAC gửi email + Slack alert đến IT team
  
Thời gian từ CrowdStrike detect đến isolation: < 5 giây
```

---

## 9. Zero-Day & Malware Lateral Spread Protection

### 9.1 Vấn đề

Zero-day malware (mã độc chưa có signature) không bị phát hiện bởi AV. Sau khi lây nhiễm một máy, malware thường **quét mạng nội bộ** (lateral movement) để tìm và lây sang các máy khác trong cùng subnet.

### 9.2 Phát hiện qua Layer-2 visibility

EasyNAC có một lợi thế độc đáo: nó lắng nghe **toàn bộ broadcast traffic** trên subnet được bảo vệ. Điều này cho phép phát hiện các pattern bất thường:

**Pattern 1 – Excessive ARP Requests**: Một máy bình thường chỉ gửi ARP Request khi cần kết nối đến IP mới. Nếu một máy đột nhiên gửi hàng trăm ARP Request đến nhiều IP khác nhau trong vài giây → đây là dấu hiệu của network scanning.

**Pattern 2 – Dark IP Scans**: EasyNAC biết IP nào đang active trong subnet (qua Device DB). Nếu có traffic đến các IP không có thiết bị nào đang sử dụng (Dark IPs) → dấu hiệu của port scanner hoặc worm đang tìm kiếm target.

**Pattern 3 – ARP Flood**: Quá nhiều ARP broadcasts trong thời gian ngắn → có thể là ARP DoS hoặc worm activity.

Khi phát hiện pattern này, EasyNAC có thể:
- Tự động quarantine thiết bị nghi vấn
- Alert admin để điều tra
- Log hành vi để forensics

---

## 10. Deception Technology – Honeypot Phân Tán

### 10.1 Kiến trúc Distributed Honeypot

EasyNAC triển khai **fake services** trên mỗi VLAN/subnet mà nó đang bảo vệ. Các service giả bao gồm:
- SSH (port 22)
- Telnet (port 23)
- FTP (port 21)
- File shares (SMB port 445)
- HTTP/HTTPS services
- Và nhiều service khác

Những service này **không có mục đích kinh doanh hợp lệ** – nghĩa là không có người dùng hay hệ thống nào cần kết nối đến chúng. Đây là tính chất quan trọng của honeypot hiệu quả: **bất kỳ ai kết nối vào đây đều là nghi phạm**.

### 10.2 Lợi thế: Near-Zero False Positives

Khác với các IDS/IPS truyền thống phải phân tích pattern phức tạp và hay có false positive, honeypot của EasyNAC có gần như **zero false positive** vì:
- Không có user thật nào được hướng dẫn kết nối vào các fake service này
- Mọi kết nối đến honeypot đều từ:
  - Automated scanner/malware đang dò mạng
  - Kẻ tấn công đang thực hiện reconnaissance

### 10.3 Detection flow

```
Kẻ tấn công đã xâm nhập một máy trong mạng:

1. Kẻ tấn công chạy port scanner (nmap, masscan, etc.)
2. Scanner phát hiện "SSH server" đang mở trên một IP
3. Kẻ tấn công thử kết nối/login → kết nối với EasyNAC honeypot
4. EasyNAC ghi nhận: IP nguồn, port đích, timestamp
5. EasyNAC xác định đây là hành vi tấn công
6. EasyNAC:
   - Quarantine thiết bị nguồn (nếu policy cho phép)
   - Gửi alert ngay lập tức đến admin
   - Log toàn bộ interaction để forensics
```

### 10.4 Tầng bảo vệ với honey service trên mỗi VLAN

Việc triển khai honeypot **trên từng VLAN** (thay vì chỉ một chỗ tập trung) có ý nghĩa chiến thuật: kẻ tấn công dù đã vượt qua perimeter firewall và đang pivot từ VLAN này sang VLAN khác đều có thể bị phát hiện sớm. Đây là lớp phòng thủ **nội bộ**, bổ sung cho firewall và IDS.

---

## 11. BYOD & Guest Access Management

### 11.1 BYOD Registration Flow

```
User mang thiết bị cá nhân vào mạng:

1. Thiết bị kết nối → EasyNAC detect → Role: UNREGISTERED BYOD
2. ARP Enforcement → HTTP/DNS redirect → Captive Portal
3. User đăng nhập Captive Portal (AD credentials hoặc social login)
4. Portal xác thực user với AD
5. Kiểm tra policy: user này được phép có bao nhiêu BYOD?
6. Nếu đã đủ số lượng → từ chối, thông báo
7. Nếu còn chỗ:
   - Ghi nhận: User X → Device Y (MAC: ...)
   - Assign BYOD Role với ACL phù hợp
   - Thiết bị được truy cập tài nguyên đã được approve
8. Admin có thể revoke BYOD registration bất kỳ lúc nào
```

### 11.2 Policy controls cho BYOD

- **Số lượng thiết bị tối đa** theo user/group
- **Loại thiết bị** được phép (chỉ iOS, chỉ Android, etc.)
- **Tài nguyên được phép**: specific subnet, specific IP ranges
- **Thời gian hết hạn**: BYOD token có thể expire
- **Tracking**: Lưu trữ lịch sử ai dùng thiết bị nào, khi nào

### 11.3 Guest Access

EasyNAC hỗ trợ hai model guest:

**Model 1 – Sponsor-based**: User nội bộ (sponsor) tạo tài khoản guest, đặt thời gian hết hạn (vài giờ đến vài ngày).

**Model 2 – Self-registration**: Guest tự tạo tài khoản qua captive portal (có thể yêu cầu email verification, điện thoại OTP). Sponsor có thể được thông báo để approve.

Cả hai đều cho phép **group registration**: tạo nhiều tài khoản cùng lúc cho một buổi họp, hội thảo, lớp học.

---

## 12. Kiến Trúc Triển Khai: 3 Phương Thức Kết Nối

EasyNAC Appliance cần Layer-2 visibility. Có 3 cách đạt được điều này:

### Method 1 – Physical Connection

Appliance cắm thêm NIC (network interface card) vào switch access port để có Layer-2 visibility cho subnet đó. Phù hợp cho môi trường nhỏ, không cần cấu hình switch.

```
[PC/Device] ──── [Access Switch] ──── [Core Switch] ──── [Internet]
                      │
                 Access Port
                      │
               [EasyNAC NIC]──── [EasyNAC Appliance] (Management NIC) ──── [Management Network]
```

### Method 2 – 802.1q Trunk

Cấu hình một **trunk port** trên switch để gửi nhiều VLAN đến Appliance. Một NIC của Appliance nhận nhiều VLAN tagged. Cho phép bảo vệ nhiều subnet từ một kết nối vật lý. Appliance tạo **sub-interface** cho mỗi VLAN.

```
[VLAN 10 devices]──┐
[VLAN 20 devices]──┤──[Switch Trunk Port]──802.1q──[EasyNAC Trunk NIC]
[VLAN 30 devices]──┘
                                                    (xử lý 3 VLAN)
```

### Method 3 – vLinks / Enforcer Sensors cho Remote Sites

Thách thức với site từ xa: không có kết nối Layer-2 trực tiếp về headquarters. Giải pháp:

**vLinks**: Thiết bị phần cứng nhỏ đặt tại site xa, tạo Layer-2 tunnel (VPN tunnel) về vLinks Central appliance hoặc về CGX Access tại HQ. Toàn bộ Layer-2 traffic từ site xa được tunnel về, giúp Appliance tập trung "nhìn thấy" và kiểm soát.

**Enforcer Sensor (software)**: Cài trên Windows/Linux/Raspberry Pi tại site xa. Sensor **tự thực hiện ARP enforcement cục bộ** và báo cáo về Appliance. Không cần kéo Layer-2 về trung tâm. Phù hợp hơn cho WAN có bandwidth hạn chế.

---

## 13. Enforcer Sensors & vLinks – Mở Rộng Bảo Vệ Chi Nhánh

### 13.1 Enforcer Sensor – Chi tiết kỹ thuật

Sensor là phần mềm chạy trên Linux/Windows/Raspberry Pi:
1. Sensor lắng nghe broadcast traffic cục bộ
2. Phát hiện thiết bị mới → báo cáo về Appliance (qua secure channel qua WAN)
3. Appliance profile thiết bị, quyết định Role
4. Appliance gửi chỉ thị về Sensor: "Device MAC XX:XX... → QUARANTINE"
5. Sensor thực hiện ARP enforcement cục bộ
6. Tất cả tính năng: compliance checks, captive portal, automated threat response đều được hỗ trợ

**Lợi ích quan trọng**: Cả môi trường **MPLS** và **NAT** đều được hỗ trợ. Tuy nhiên, trong môi trường NAT, khả năng profiling đầy đủ có thể bị hạn chế vì Appliance không nhìn thấy Layer-2 traffic của các thiết bị đứng sau NAT.

### 13.2 Agent tùy chọn – Khi nào cần?

EasyNAC có thể cài **agent** trên Windows/Linux endpoint để tăng cường khả năng:
- **Compliance checks chi tiết hơn**: running processes, registry values, specific files, custom scripts
- **Phát hiện nhanh hơn**: trong vòng **10 giây** thay vì phụ thuộc polling interval
- **Real-time Wi-Fi control**: khi endpoint kết nối vào mạng có dây của công ty, agent tự động **tắt Wi-Fi adapter** để ngăn dual-homing (kết nối đồng thời cả wired lẫn wireless)
- **Automatic remediation**: khi compliance check thất bại, agent tự chạy script khắc phục (ví dụ: start AV update)
- **Pop-up notifications**: hiển thị thông báo trực tiếp cho user

---

## 14. VPN Inline Enforcement

### 14.1 Vấn đề VPN

Hầu hết NAC hoạt động trên LAN. Nhưng với remote workers kết nối qua VPN, thiết bị đầu cuối có thể đang ở nhà, không được kiểm soát, không comply với security policy. VPN truyền thống không kiểm tra endpoint posture.

### 14.2 Inline Mode cho VPN

EasyNAC Appliance được đặt ở **bridge mode** (inline) giữa VPN server và phần mạng nội bộ được bảo vệ:

```
[Remote User] ──VPN tunnel──► [VPN Server] ──► [EasyNAC Appliance] ──► [Internal Network]
                                                      │
                                          (kiểm tra compliance)
                                                      │
                              ┌───────────────────────┴──────────────────────┐
                              │                                               │
                    [Compliant → PASS]                           [Non-compliant → BLOCK]
                              │                                               │
                    [Traffic forwarded]                           [Redirect to remediation]
```

Agent được **bắt buộc** trong mode này (khác với LAN agentless). Agent trên endpoint giao tiếp với Appliance để xác nhận compliance.

**Kết hợp Fingerprint làm 2FA**: Agent có unique serial number. Khi user VPN vào với đúng credential nhưng từ thiết bị khác → fingerprint không khớp → bị chặn. Đây là một dạng transparent device-based 2FA.

---

## 15. High Availability (HA)

EasyNAC hỗ trợ HA theo mô hình **active-passive two-box design**:

```
[Primary Appliance] ──sync─── [Backup Appliance]
       │                              │
    (Active)                      (Standby)
       │
[Network devices]
```

Cơ chế:
- Primary **sync liên tục** database và configuration sang Backup
- Backup **monitor** Primary (heartbeat)
- Nếu Backup xác định Primary offline → **Backup tự động become Active**
- Khi Primary trở lại online: Backup sync ngược lại, Primary trở thành Active

**Fail-open design**: Vì EasyNAC là **out-of-band** (không nằm inline với traffic thông thường), nếu toàn bộ Appliance fail → network tiếp tục hoạt động bình thường (chỉ mất khả năng enforcement). Đây là đặc tính quan trọng: không bao giờ tạo single point of failure cho network connectivity.

---

## 16. Central Visibility Manager (CVM)

Dành cho tổ chức có nhiều Appliance tại nhiều địa điểm:

**Tính năng chính:**
- **Consolidated Dashboard**: Nhìn toàn cảnh tất cả devices, events trên mọi site
- **Policy Synchronization**: Deploy policy thay đổi đến nhiều Appliance đồng thời
- **License Management**: Chia sẻ license pool giữa các Appliance (tối ưu hóa chi phí)
- **Device Roaming**: Khi user di chuyển giữa các site, device được nhận ra và áp dụng policy đúng
- **Automated Backups**: CVM tự động backup cấu hình của tất cả Appliance
- **Firmware Management**: Đơn giản hóa việc cập nhật firmware cho nhiều thiết bị
- **Aggregated Reporting**: Báo cáo tổng hợp có thể xem theo toàn bộ hoặc theo region/site

---

## 17. Tích Hợp Hệ Sinh Thái Bảo Mật

EasyNAC 3.2 tích hợp với danh sách rộng lớn các giải pháp:

### Identity & Directory
- Microsoft Active Directory / Entra ID (Azure AD)
- OKTA Verify

### Endpoint Security / XDR
- CrowdStrike Falcon
- SentinelOne
- Palo Alto Cortex XDR
- Microsoft Defender
- Microsoft Intune
- Carbon Black Endpoint Standard
- Cybereason
- Elastic Open XDR
- FireEye HX
- Trellix ePolicy Orchestrator

### Antivirus
- ESET Antivirus
- Kaspersky Antivirus
- Sophos Central
- Bitdefender
- Symantec Endpoint Protection
- Trend Micro (OfficeScan, Apex Central, Vision One)
- Webroot

### Patch & Endpoint Management
- HCL BigFix
- Ivanti Security Controls
- Kaseya VSA
- ManageEngine Desktop Central / Patch Manager
- Microsoft SCCM / WSUS
- SolarWinds Observability
- 42 Gears SureMDM

### Vulnerability Management
- Tenable Vulnerability Management

### Specialty
- Moscii StarCat

**Cơ chế tích hợp**: Thông qua API của từng vendor. EasyNAC query API để lấy trạng thái compliance theo lịch định kỳ. Không cần agent trên endpoint để thực hiện compliance check – chỉ cần kết nối API từ Appliance đến management server của từng giải pháp.

---

## 18. Compliance Checks & Endpoint Posture Validation

### 18.1 Agentless Compliance Checks

Thông qua API integration:
- **AV Check**: AV có được cài không? Agent đang active không? Definitions có up-to-date không? (dựa trên policy: ví dụ không được cũ hơn 3 ngày)
- **Patch Check**: Các critical patches đã được cài chưa? (thông qua patch management API)
- **Domain Check**: Thiết bị có join domain không? (thông qua AD LDAP query)
- **MDM Check**: Thiết bị di động có được enrolled trong MDM không?

### 18.2 Agent-based Compliance Checks (tùy chọn)

Với agent, kiểm tra chi tiết hơn:
- Running processes và version
- Registry values (ví dụ: firewall enabled = 1)
- File existence và version (ví dụ: specific security software)
- Machine name và OS version
- Custom scripts

### 18.3 Dynamic Re-check

Compliance không được kiểm tra một lần khi kết nối. Appliance **định kỳ poll** các management server để kiểm tra lại. Nếu AV của một máy bị tắt giữa chừng → phát hiện tại lần poll tiếp theo → hạ Role tự động.

---

## 19. Licensing & Sizing

### 19.1 Mô hình License

EasyNAC dùng mô hình **Concurrent Device License** dựa trên **unique MAC address**:
- Chỉ đếm thiết bị **active trong 5 phút gần nhất**
- Thiết bị Untrusted (bị block/quarantine) **không tiêu thụ license**
- Agents được mua riêng, không gộp trong base license

**Hình thức bán:**
- **Perpetual License**: Cho virtual appliance hoặc hardware appliance – trả một lần, dùng mãi
- **Subscription**: Trả hàng năm

### 19.2 Appliance Capacity

| Model | Max Devices | Max VLANs |
|---|---|---|
| Small | đến vài trăm | đến 10 |
| Medium | vài nghìn | đến 100 |
| Large | đến 200,000+ | đến 200 |

*Capacity thực tế phụ thuộc vào số VLAN, endpoint, và các tính năng được bật*

### 19.3 Grace Period

Nếu license bị vượt quá:
- **Vượt < 10%**: Cảnh báo hiển thị trên dashboard, hệ thống hoạt động bình thường
- **Vượt > 10%**: Enforcement bị tắt cho phần thiết bị trusted vượt ngưỡng (untrusted vẫn bị block)

### 19.4 Sizing Guidelines

Khi sizing, cần đếm **tất cả thiết bị** trên subnet được bảo vệ, bao gồm:
- PC, laptop
- Máy in, máy scan
- Switch, AP (nếu trên cùng subnet)
- IoT devices
- VoIP phones

Subnet không được bảo vệ (ví dụ: server segment, VoIP segment nếu không yêu cầu kiểm soát) không cần license.

---

## 20. So Sánh với NAC Truyền Thống (802.1X)

| Tiêu chí | EasyNAC (ARP-based) | NAC 802.1X truyền thống |
|---|---|---|
| **Thay đổi switch** | Không cần | Bắt buộc (802.1X enabled) |
| **Switch requirement** | Mọi loại switch, kể cả unmanaged | Switch phải hỗ trợ 802.1X |
| **RADIUS server** | Không cần | Bắt buộc |
| **Supplicant trên endpoint** | Không cần | Thường cần |
| **Thời gian triển khai** | Ngày đến tuần | Tháng |
| **IoT/OT support** | Tốt (agentless, không cần supplicant) | Khó (IoT thường không có supplicant) |
| **Phát hiện thiết bị** | Tức thì (Layer-2 broadcast) | Phụ thuộc vào supplicant |
| **Granularity enforcement** | Per-device, per-VLAN | Per-port (switch port level) |
| **Fail-open khi appliance fail** | Có (out-of-band) | Phụ thuộc cấu hình |
| **Honeypot** | Built-in | Không có |
| **Lateral spread detection** | Built-in (Layer-2 monitoring) | Không có |
| **Chi phí tổng thể** | Thấp hơn | Cao hơn |

---

## 21. Điểm Mạnh, Giới Hạn & Đánh Giá Tổng Quan

### Điểm mạnh

**1. Triển khai thực sự đơn giản**: Không cần thay đổi bất kỳ thiết bị mạng nào. Đây là lợi thế lớn nhất, đặc biệt với tổ chức có nhiều site.

**2. Bảo mật sâu hơn NAC truyền thống trong một số khía cạnh**: ARP enforcement ngăn lateral movement ngay tại Layer-2, ngay cả khi hai máy cùng VLAN – điều mà 802.1X không làm được.

**3. Deception technology tích hợp sẵn**: Không cần mua riêng giải pháp honeypot – EasyNAC có sẵn và phủ toàn bộ VLAN.

**4. Automated Threat Response thực sự nhanh**: Từ lúc nhận syslog alert đến khi cô lập thiết bị chỉ vài giây, không cần can thiệp thủ công.

**5. IoT/OT friendly**: Không yêu cầu supplicant hay agent → phù hợp cho thiết bị IoT, máy in, camera, PLC không thể cài thêm phần mềm.

**6. Kinh tế cho multi-site**: Enforcer Sensor rẻ (chạy trên Raspberry Pi) giúp mở rộng bảo vệ đến hàng nghìn site với chi phí thấp.

### Giới hạn & lưu ý

**1. IPv6**: ARP enforcement là cơ chế IPv4. Môi trường thuần IPv6 cần phương pháp enforcement khác. Dual-stack được hỗ trợ nhưng không khuyến nghị cho môi trường IPv6-only.

**2. Môi trường NAT**: Appliance có thể không profile đầy đủ các thiết bị đứng sau NAT do không thấy trực tiếp Layer-2 traffic.

**3. Phụ thuộc Layer-2 connectivity**: Appliance cần có Layer-2 visibility đến subnet được bảo vệ. Môi trường routing thuần túy không có trunk port hay Enforcer Sensor sẽ cần giải pháp bổ sung.

**4. ARP Spoofing defense không hoàn hảo 100%**: Với kẻ tấn công tinh vi có thể replay ARP flooding nhanh hơn Appliance có thể gửi corrections – tuy nhiên đây là tình huống hiếm gặp và phức tạp.

**5. Agent cần thiết cho VPN và một số compliance check nâng cao**: Khi cần bảo vệ VPN hoặc cần compliance check chi tiết (registry, processes), agent là bắt buộc – mâu thuẫn một phần với tuyên bố "agentless".

### Kết luận

EasyNAC là lựa chọn hấp dẫn cho các tổ chức muốn triển khai NAC nhanh, đặc biệt khi:
- Hạ tầng mạng đa dạng, không thể đồng nhất hóa switch lên 802.1X
- Có nhiều IoT/OT devices cần kiểm soát
- Có nhiều site từ xa với IT staff hạn chế
- Cần tích hợp sâu với hệ sinh thái XDR/EDR hiện có
- Muốn thêm Deception/honeypot mà không muốn quản lý thêm sản phẩm riêng

Với những tổ chức đã có 802.1X hoàn chỉnh, EasyNAC vẫn có thể là lớp bổ sung giá trị với các tính năng độc đáo như ARP-based lateral movement detection, distributed honeypot, và automated threat response tích hợp.

---

