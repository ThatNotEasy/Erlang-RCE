import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

PATCHED_VERSIONS = {
    "25": "25.3.2.20",
    "26": "26.2.5.11",
    "27": "27.3.3"
}

def get_ssh_banner(ip, port=22, timeout=2):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner
    except Exception:
        return None

def compare_versions(current, fixed):
    def normalize(v): return [int(x) for x in v.split(".")]
    return normalize(current) >= normalize(fixed)

def analyze_banner(ip, banner):
    if not banner:
        return f"{ip}: ❌ No SSH / No Banner"

    if "Erlang" in banner or "OTP" in banner:
        match = None
        if "OTP-" in banner:
            match = banner.split("OTP-")[-1].split()[0]
        elif "Erlang/" in banner:
            match = banner.split("Erlang/")[-1].split()[0]

        if match:
            version = match.strip()
            major = version.split(".")[0]
            fixed = PATCHED_VERSIONS.get(major)

            if fixed and not compare_versions(version, fixed):
                return f"{ip}: 🚨 Erlang SSH VULNERABLE - Version {version} < {fixed} | Banner: {banner}"
            else:
                return f"{ip}: ✅ Erlang SSH PATCHED - Version {version} | Banner: {banner}"
        else:
            return f"{ip}: ⚠️ Erlang SSH Detected - Unknown Version | Banner: {banner}"
    else:
        return f"{ip}: ✅ SSH Open (non-Erlang) | Banner: {banner}"

def scan_ip(ip):
    ip = ip.strip()
    if not ip:
        return None
    banner = get_ssh_banner(ip)
    return analyze_banner(ip, banner)

def main():
    parser = argparse.ArgumentParser(description="Check remote SSH for Erlang/OTP RCE vulnerability")
    parser.add_argument("-f", "--file", required=True, help="File containing IP addresses to scan")
    parser.add_argument("-t", "--thread", type=int, default=10, help="Number of threads to use")
    args = parser.parse_args()

    try:
        with open(args.file, 'r') as f:
            ip_list = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ File not found: {args.file}")
        return

    print(f"🔍 Scanning {len(ip_list)} IPs with {args.thread} threads...\n")

    with ThreadPoolExecutor(max_workers=args.thread) as executor:
        futures = {executor.submit(scan_ip, ip): ip for ip in ip_list}
        for future in as_completed(futures):
            result = future.result()
            if result:
                print(result)

if __name__ == "__main__":
    main()
