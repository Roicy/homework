import ssl
import socket
import threading
import queue
import tkinter as tk


def get_ssl_info(host, port):
    try:
        # 创建SSL上下文
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # 获取密码套件信息
                cipher = ssock.cipher()
                cipher_label.config(text=f"Cipher: {cipher[0]}")

                # 获取证书信息
                cert = ssock.getpeercert()
                cert_text = "Certificate:\n"
                for key, value in cert.items():
                    cert_text += f"{key}: {value}\n"
                cert_label.config(text=cert_text)
    except ssl.SSLError as e:
        cipher_label.config(text=f"SSL error occurred: {e}")
    except socket.error as e:
        cipher_label.config(text=f"Socket error occurred: {e}")


def scan_https_servers(hosts, port, num_threads):
    # 创建队列用于存储待扫描的主机
    host_queue = queue.Queue()
    for host in hosts:
        host_queue.put(host)

        # 创建线程池
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=scan_worker, args=(host_queue, port))
        t.start()
        threads.append(t)

        # 等待所有线程完成
    for t in threads:
        t.join()


def scan_worker(host_queue, port):
    while not host_queue.empty():
        host = host_queue.get()
        get_ssl_info(host, port)


def start_scan():
    hosts = hosts_entry.get().split(",")
    port = int(port_entry.get())
    num_threads = int(threads_entry.get())
    scan_https_servers(hosts, port, num_threads)


# 创建主窗口
window = tk.Tk()
window.title("HTTPS Scanner")

# 创建输入框和标签
hosts_label = tk.Label(window, text="Hosts (comma-separated):")
hosts_label.pack()
hosts_entry = tk.Entry(window)
hosts_entry.pack()

port_label = tk.Label(window, text="Port:")
port_label.pack()
port_entry = tk.Entry(window)
port_entry.pack()

threads_label = tk.Label(window, text="Number of Threads:")
threads_label.pack()
threads_entry = tk.Entry(window)
threads_entry.pack()

# 创建扫描按钮
scan_button = tk.Button(window, text="Start Scan", command=start_scan)
scan_button.pack()

# 创建显示SSL信息的标签
cipher_label = tk.Label(window, text="")
cipher_label.pack()

cert_label = tk.Label(window, text="")
cert_label.pack()

# 运行主循环
window.mainloop()  
