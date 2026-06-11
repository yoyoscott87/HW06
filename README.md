# HW06

# TLS VPN (TAP + OpenSSL) 實作說明

檔案清單：

| 檔案 | 說明 |
|---|---|
| `common.h` | TAP 建立、可靠 I/O、relay thread 等共用程式 |
| `vpn_server.c` | Gateway 端 (VM2)，監聽 TLS 連線 |
| `vpn_client.c` | User 端 (VM1)，主動連線到 Gateway |
| `Makefile` | 編譯腳本 |
| `gen_certs.sh` | 產生 CA / server / client 憑證 |

封包格式：`[2 bytes 長度 (network byte order)][TAP 讀出的 Ethernet frame]`，
client/server 收到後依長度切回原始 frame 並寫入自己的 tap 介面。

---

## 0. 環境準備（兩台 VM 都要）

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev openssl iproute2 iptables
```

---

## 1. 產生憑證（在任一台機器上執行一次即可）

```bash
chmod +x gen_certs.sh
./gen_certs.sh
```

執行後會產生：

```
ca-key.pem  ca-cert.pem
server-key.pem  server-cert.pem   (CN=vpn-server, SAN=IP:192.168.2.1)
client-key.pem  client-cert.pem   (CN=vpn-client)
```

複製檔案：

- **VM2 (Gateway, 192.168.2.1)**：`ca-cert.pem`、`server-cert.pem`、`server-key.pem`
- **VM1 (User, 192.168.2.3)**：`ca-cert.pem`、`client-cert.pem`、`client-key.pem`

> `server-cert.pem` 內含 `subjectAltName=IP:192.168.2.1`，client 會用
> `X509_VERIFY_PARAM_set1_ip_asc()` 驗證這個 IP，所以 client 連線時要打
> `192.168.2.1`（與下方步驟一致）。
>
> server 端設定 `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT`，
> 強制 client 出示憑證 → **mutual TLS**。

---

## 2. 編譯（兩台 VM 都要各自編譯一份）

把對應的 `.c` / `.h` / `Makefile` 與憑證放在同一個目錄下，執行：

```bash
make
```

VM2 會用到 `vpn_server`，VM1 會用到 `vpn_client`（兩邊都編譯出來也無妨，
只跑各自需要的執行檔即可）。

---

## 3. VM2（Gateway, 192.168.2.1）啟動 server

`vpn_server` 程式會自動：

- 建立 `tap0` 並設成 `10.10.10.3/24`、`up`
- 開啟 `net.ipv4.ip_forward=1`
- 加入 `iptables FORWARD` 規則，允許 `10.10.10.0/24 <-> 172.16.0.0/24`
- 監聽 TCP（預設 4433）等待 TLS 連線

```bash
cd tls_vpn
sudo ./vpn_server          # 預設監聽 4433
# 或指定 port: sudo ./vpn_server 4433
```

確認 VM2 對 VM3 的路由已存在（VM2 與 VM3 同處 172.16.0.0/24，通常不需額外
設定；如非同網段才需要 `ip route add 172.16.0.0/24 via <next-hop>`）。

---

## 4. VM1（User, 192.168.2.3）啟動 client

`vpn_client` 程式會自動：

- 建立 `tap0` 並設成 `10.10.10.2/24`、`up`
- 加入路由 `172.16.0.0/24 via 10.10.10.3 dev tap0`（必須指定 `via`，否則
  kernel 會對 172.16.0.2 做 ARP 而失敗，回報 Host Unreachable）
- 連線到 Gateway 並完成 mutual TLS handshake

```bash
cd tls_vpn
sudo ./vpn_client 192.168.2.1          # 預設連到 4433
# 或指定 port: sudo ./vpn_client 192.168.2.1 4433
```

兩端印出 `[*] TLS handshake OK (cipher: ...)` 代表連線成功。

---

## 5. 驗證 VPN 是否生效


### 5.1 啟動前：證明沒有 VPN 就到不了內網

在 **VM1** 上，確保 `vpn_client` 尚未啟動（或先 Ctrl+C 結束）：

```bash
ip route show | grep 172.16   # 應該沒有任何結果
ping -c 2 172.16.0.2          # 應該失敗 (Network unreachable)
```
<img width="777" height="155" alt="image" src="https://github.com/user-attachments/assets/6ef57511-f833-4b61-bce0-02dd38a9e654" />

→ 在沒有 VPN 的情況下，VM1 本來就無法存取 172.16.0.0/24。

### 5.2 啟動 VPN，確認 mutual TLS handshake 成功

依照第 3、4 節分別在 VM2、VM1 啟動 `vpn_server` / `vpn_client`，截圖兩端輸出：

- VM2：

  <img width="960" height="440" alt="image" src="https://github.com/user-attachments/assets/828f9969-8e34-443b-be67-067b9a2be1c3" />


- VM1：
  <img width="960" height="440" alt="image" src="https://github.com/user-attachments/assets/4751e7e1-a5fd-4cc9-b764-895e2fde5fd7" />


→ 兩端同時出現 `TLS handshake OK`，證明憑證鏈驗證成功、mutual TLS 建立完成。

### 5.3 確認 tap 介面與路由設定

VM1：

```bash
ip addr show tap0             # 應顯示 10.10.10.2/24
ip route show | grep 172.16   # 應顯示 172.16.0.0/24 via 10.10.10.3 dev tap0
```

VM2：

```bash
ip addr show tap0             # 應顯示 10.10.10.3/24
sysctl net.ipv4.ip_forward    # 應為 1
iptables -L FORWARD -v -n     # 應看到 10.10.10.0/24 <-> 172.16.0.0/24 的 ACCEPT 規則
```

### 5.4 連通性測試（核心證據）

在 **VM1** 上：

```bash
ping -c 4 10.10.10.3      # 測試 tunnel 本身 (VM1 <-> VM2 tap)
ping -c 4 172.16.0.2      # 經由 tunnel + VM2 forward 到 VM3，TTL 應為 63
traceroute 172.16.0.2     # 應可看到 10.10.10.3 為中繼跳點
```

`ping 172.16.0.2` 從 100% packet loss 變成全部 reply，且 TTL=63（經過 VM2
一跳），是「VPN 生效、可存取內網主機」最直接的證據。

在 **VM2** 上可用 `iptables -L FORWARD -v -n` 再看一次，確認 ACCEPT 規則的
封包/位元組計數有增加。

### 5.5 證明流量確實有被 TLS 加密（推薦，加分項）

跑 `ping -c 4 172.16.0.2`（在 VM1）的同時，分別在兩個地方用 `tcpdump`
觀察同一份封包：

**(a) tap0（VPN 內部，明文）**

```bash
sudo tcpdump -ni tap0 -X icmp
```

→ 可以看到完整明文的 ICMP echo request/reply。

**(b) 實體網卡（192.168.2.0/24，VM1↔VM2 之間，加密後）**

```bash
sudo tcpdump -ni enp0s8 -X host 192.168.2.1
```
（介面名稱依實際環境調整，VM1 上對應 192.168.2.0/24 的網卡）

→ 應只看到 TLS Application Data，看不到任何 ICMP 字樣或明文內容。

兩張截圖並列，說明「同一份 ICMP 封包，在 tap0 是明文，在實體網卡上已被
TLS 加密成 Application Data」，即可證明加密生效。


## 6. 三台 VM 的網路/路由設定總覽

下表整理整個環境最終需要的網路設定，方便對照與寫進報告。「來源」欄標示
該設定是程式自動執行，還是需要手動下指令。

### VM1（User, 192.168.2.3）

| 設定項目 | 指令 | 來源 |
|---|---|---|
| tap0 介面啟用 | `ip link set dev tap0 up` | `vpn_client` 自動執行 |
| tap0 IP | `ip addr add 10.10.10.2/24 dev tap0` | `vpn_client` 自動執行 |
| 內網路由 | `ip route add 172.16.0.0/24 via 10.10.10.3 dev tap0` | `vpn_client` 自動執行 |

### VM2（Gateway, 192.168.2.1）

| 設定項目 | 指令 | 來源 |
|---|---|---|
| tap0 介面啟用 | `ip link set dev tap0 up` | `vpn_server` 自動執行 |
| tap0 IP | `ip addr add 10.10.10.3/24 dev tap0` | `vpn_server` 自動執行 |
| 開啟 IP forwarding | `sysctl -w net.ipv4.ip_forward=1` | `vpn_server` 自動執行 |
| FORWARD 規則（VPN → 內網） | `iptables -A FORWARD -i tap0 -s 10.10.10.0/24 -d 172.16.0.0/24 -j ACCEPT` | `vpn_server` 自動執行 |
| FORWARD 規則（內網 → VPN） | `iptables -A FORWARD -o tap0 -d 10.10.10.0/24 -s 172.16.0.0/24 -j ACCEPT` | `vpn_server` 自動執行 |
| 內網介面 IP（既有） | `enp0s9: 172.16.0.1/24`（連到 172.16.0.0/24，附帶產生路由 `172.16.0.0/24 dev enp0s9`） | VM 環境既有設定，無需另外指令 |

### VM3（內網主機, 172.16.0.2）

| 設定項目 | 指令 | 來源 |
|---|---|---|
| 設定介面 IP | `sudo ip addr add 172.16.0.2/24 dev enp0s8` | **手動執行**（VM3 該網卡原本沒有 IP） |
| 回程路由 | `sudo ip route add 10.10.10.0/24 via 172.16.0.1` | **手動執行**（讓回給 10.10.10.0/24 的封包經由 VM2 送回） |

> 以上 `ip addr` / `ip route` / `sysctl` / `iptables` 指令皆為**暫時性**，
> 重開機或介面重置後會消失。`vpn_client`/`vpn_server` 每次啟動時會重新
> 執行其負責的部分；VM3 的兩條手動指令則需在每次測試前（或重開機後）
> 重新執行一次，或自行寫入 netplan / `/etc/network/interfaces` 做永久設定。

---

## 7. 確認/補充項目

- VM2 若有預設防火牆策略 `DROP`，記得確認 `FORWARD` policy 不會擋掉
  程式加入的 ACCEPT 規則之外的封包（必要時自行調整）。
- VM3（172.16.0.2）需要設定回程路由，讓往 `10.10.10.0/24` 的回應封包
  能送回 VM2（例如把 VM2 設為其預設閘道，或加一條
  `ip route add 10.10.10.0/24 via <VM2 在172.16網段的IP>`）。
- 結束程式：`Ctrl+C`。`vpn_client`/`vpn_server` 結束後，`tap0`、路由規則、
  iptables 規則不會自動清除，需要的話手動 `ip link delete tap0` 等指令清理，
  或重新開機。
- `vpn_server` 採單一連線設計：client 斷線後會回到 accept 狀態，等待下一次
  `vpn_client` 連入，`tap0` 與 forwarding 設定會持續保留。
