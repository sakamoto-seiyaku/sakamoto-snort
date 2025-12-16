# DNS Socket 名称不匹配故障排查

## 故障现象

- 前端 App 无 DNS 数据
- PKTSTREAM 有数据，DNSSTREAM 无数据
- 统计中 dns 全为 0，但 rxp/txp 有值

---

## 常见问题处理

### A. 进程找不到

`ps -A | grep snort` 可能因进程名截断而找不到。

正确方法：
```bash
# 方法1：pidof
adb shell "su -c 'pidof sucre-snort-dev'"

# 方法2：lsof 查 socket 占用
adb shell "su -c 'lsof 2>/dev/null | grep sucre-snort | head -5'"

# 方法3：查 /proc/net/unix
adb shell "su -c 'cat /proc/net/unix | grep sucre'"
```

### B. 连接失败/超时

错误的端口转发：
```bash
# 错误：TCP 到 TCP
adb forward tcp:60606 tcp:60606

# 正确：TCP 到 Unix Socket
adb forward tcp:60606 localfilesystem:/dev/socket/sucre-snort-control
```

### C. 进程启动失败（socket bind error）

错误信息：
```
failed to bind abstract fallback socket
```

原因：旧进程仍占用 socket。

处理：
```bash
# 1. 找到占用进程的 PID
adb shell "su -c 'lsof 2>/dev/null | grep sucre-snort-netd | head -1'"
# 输出示例：sucre-snort-dev 32007 root ...

# 2. 强制杀死
adb shell "su -c 'kill -9 32007'"

# 3. 清理 socket 文件
adb shell "su -c 'rm -f /dev/socket/sucre-snort-control /dev/socket/sucre-snort-netd'"

# 4. 重新启动
adb shell "su -c 'cd /data/snort && /data/local/tmp/sucre-snort-dev &'"
```

### D. 完整重启流程

```bash
# 一条命令完成
adb shell "su -c 'killall -9 sucre-snort-dev 2>/dev/null; rm -f /dev/socket/sucre-snort-*; sleep 1; cd /data/snort && /data/local/tmp/sucre-snort-dev &'"

# 验证
sleep 2
adb shell "su -c 'pidof sucre-snort-dev'"
```

### E. 验证连接

```bash
# 设置转发
adb forward tcp:60606 localfilesystem:/dev/socket/sucre-snort-control

# 测试 HELLO
python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', 60606), timeout=5)
s.sendall(b'HELLO\x00')
print(s.recv(1024))
s.close()
"
# 预期输出：b'OK\x00'
```

---

## DNS 无数据排查步骤

### 1. 确认进程运行

```bash
adb shell "su -c 'pidof sucre-snort-dev'"
```

预期：返回 PID

### 2. 设置端口转发

```bash
adb forward tcp:60606 localfilesystem:/dev/socket/sucre-snort-control
```

### 3. 查询统计数据

```bash
python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', 60606), timeout=5)
s.sendall(b'ALL.A\x00')
s.settimeout(2)
data = b''
while True:
    try:
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
        if data.endswith(b'\x00'): break
    except socket.timeout: break
s.close()
print(data.rstrip(b'\x00').decode())
"
```

预期：dns.total 全为 [0,0,0]，但 rxp/txp 有值

### 4. 采样 DNSSTREAM

```bash
python3 -c "
import socket, time
s = socket.create_connection(('127.0.0.1', 60606), timeout=10)
s.sendall(b'DNSSTREAM.START 120 1\x00')
s.settimeout(0.5)
data = b''
end = time.time() + 3
while time.time() < end:
    try:
        chunk = s.recv(4096)
        if chunk: data += chunk
    except socket.timeout: pass
s.sendall(b'DNSSTREAM.STOP\x00')
s.close()
print(f'Received: {len(data)} bytes')
"
```

预期：0 bytes（无 DNS 事件）

### 5. 采样 PKTSTREAM（对比）

```bash
python3 -c "
import socket, time
s = socket.create_connection(('127.0.0.1', 60606), timeout=10)
s.sendall(b'PKTSTREAM.START 120 1\x00')
s.settimeout(0.5)
data = b''
end = time.time() + 2
while time.time() < end:
    try:
        chunk = s.recv(4096)
        if chunk: data += chunk
    except socket.timeout: pass
s.sendall(b'PKTSTREAM.STOP\x00')
s.close()
print(f'Received: {len(data)} bytes')
"
```

预期：有数据（>0 bytes）

### 6. 检查 libnetd_resolv.so 中的 socket 名称

```bash
adb shell "su -c 'strings /apex/com.android.resolv/lib64/libnetd_resolv.so | grep sucre'"
```

输出：
```
sucre-snort DNSProxListener connect error
sucre-snort DNSProxListener socket error
sucre-snort DNSProxListener setsockopt error
@sucre-snort-inetd          <-- 注意这里
sucre-snort DNSProxListener socket r/w error
```

### 7. 检查 sucre-snort 监听的 socket 名称

```bash
adb shell "su -c 'cat /proc/net/unix | grep sucre'"
```

输出：
```
... /dev/socket/sucre-snort-netd
... @sucre-snort-netd       <-- 注意这里
```

## 结论

**Socket 名称不匹配**：
- libnetd_resolv.so 连接：`@sucre-snort-inetd`
- sucre-snort 监听：`@sucre-snort-netd`

## 修复

修改 `sucre/sucre-snort/src/Settings.hpp:86`：

```cpp
// 修改前
static constexpr const char *netdSocketPath = "sucre-snort-netd";

// 修改后
static constexpr const char *netdSocketPath = "sucre-snort-inetd";
```

重新编译部署：
```bash
cd scripts/dev
bash dev-build.sh && bash dev-deploy.sh
```
