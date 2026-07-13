import socket, time

target_ip = socket.gethostbyname('example.com')
print(f"Target: {target_ip}:80")

for i in range(5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        t0 = time.time()
        s.connect((target_ip, 80))
        s.send(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        resp = s.recv(1024)
        t1 = time.time()
        print(f"Round {i+1}: RTT={1000*(t1-t0):.1f} ms, first bytes: {resp[:50]}")
        s.close()
        time.sleep(2)  # 间隔 2 秒，便于观察
    except Exception as e:
        print(f"Round {i+1} failed: {e}")
        time.sleep(2)