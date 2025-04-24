# 🔐 Erlang/OTP SSH RCE Vulnerability Scanner

A fast and lightweight Python tool to detect **exposed Erlang/OTP SSH servers** vulnerable to **unauthenticated Remote Code Execution (RCE)**.

---

## 📌 About the Vulnerability

A critical security flaw has been identified in the **Erlang/OTP SSH server**, allowing remote attackers to execute arbitrary code **without authentication**. The vulnerability affects **all versions** unless patched.

> 💥 Impact: Full remote code execution  
> ⚠️ Affected: All unpatched Erlang/OTP SSH deployments  
> 🛡️ Mitigation: Update to OTP `27.3.3`, `26.2.5.11`, or `25.3.2.20`  
> 🔗 [Erlang Advisory](https://www.erlang.org/news/170)
