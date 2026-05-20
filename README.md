# Secure Medical Operating System (Hardened xv6)

A hardened, highly secure version of the xv6 operating system customized for critical medical device environments (such as insulin pumps and patient monitors). This project implements robust user identity management, Role-Based Access Control (RBAC), and an isolated, kernel-level automated auditing subsystem compliant with medical cybersecurity frameworks.

---

# By Mohamed Magdy Hagras, Reg. 221010763, CCY4304, Lecturers : Prof.Dr Ayman adel - Ta Abdelrahman soliman .

# Key Features Implemented

## 🛡️ Phase 1 & 2: User Identity & Role-Based Access Control (RBAC)

* **Multi-User Architecture:**
  Support for distinct users (`admin`, `patient1`, `doctor1`) mapped to specific User IDs (`UID 0`, `UID 1`, `UID 2`).

* **Authentication System:**
  Secure authentication mechanism validating usernames and passwords using the custom `auth` and `useradd` utilities.

* **Granular File Permissions:**
  Hardened standard tools (`chmod`, `chown`) enforcing strict read/write constraints on medical assets:

| Protected Resource    | Access Policy                                         |
| --------------------- | ----------------------------------------------------- |
| `/patient/records`    | Accessible only by Patient (`UID 1`, Read-Only `400`) |
| `/dosage/insulin.log` | Accessible by Doctor (`UID 2`, Read-Write `644`)      |
| `/device/config`      | Strict Admin isolation (`UID 0`, Read-Write `600`)    |

---

## 📊 Phase 3: Persistent Kernel Audit Ring Buffer

* **Kernel-Level Syscall Auditing:**
  Real-time interception of sensitive system calls (`open`, `write`, `exec`, `fork`, `whoami`, `auth`) capturing:

  * Tick Time
  * PID
  * UID
  * Syscall Name

* **Circular Ring Buffer Architecture:**
  A protected 32-slot kernel ring buffer implemented inside kernel space to preserve security events across continuous execution.

* **Root-Only Audit Access:**
  The `audit_read` utility enforces strict root validation inside the kernel. Unauthorized access attempts return:

  ```text
  EPERM: Access denied
  ```

* **Noise Filtering:**
  Smart filtering prevents asynchronous keyboard interrupt spam from polluting the audit trail.

---

# + Bonus Phase: Automated Security Compliance & Test Matrix

* **Single-Command Automated Validation:**
  Running:

  ```bash
  security_test
  ```

  automatically:

  1. Initializes the environment using `medsetup`
  2. Executes a 12-case security validation matrix
  3. Produces a compliance report

* **Integration Security Flow:**
  Demonstrates:

  ```text
  Attack Attempt → Permission Denied → Audit Logged → Detection Verified
  ```

* **Compliance Output:**
  Generates PASS/FAIL reporting directly from kernel-level audit evidence.

---

# 📁 Repository Structure

```text
.
├── XV6-Secure-Medical-OS/
│   ├── kernel/
│   │   ├── sysproc.c
│   │   ├── syscall.c
│   │   ├── syscall.h
│   │   └── trap.c
│   │
│   ├── user/
│   │   ├── medsetup.c
│   │   ├── audit_read.c
│   │   └── security_test.c
│   │
│   └── Makefile
│
├── fs.img
└── README.md
```

---

# 🛠️ Installation & Automated Testing

## Prerequisites

Ensure the following are installed on your Linux distribution:

* RISC-V GNU Toolchain
* QEMU Emulator

Recommended platforms:

* Ubuntu
* Kali Linux

---

#  Quick Start

## 1) Enter Project Directory

```bash
cd XV6-Secure-Medical-OS
```

## 2) Compile and Launch xv6

```bash
make clean && make qemu
```

## 3) Login Using Default Administrator Credentials

```text
Username: admin
Password: admin123
```

## 4) Execute Automated Security Compliance Tests

```bash
security_test
```

---

# 📋 Expected Compliance Output

```text
Automation Trigger: Running medsetup to initialize environment...
Initializing Medical OS Security Environment...
Please wait...

====================================================
FINAL SECURITY SETUP SUMMARY
====================================================

Users Created:
- patient1 (UID 1)
- doctor1 (UID 2)

----------------------------------------------------
File Path               Owner UID       Permissions
----------------------------------------------------
/patient/records        1 (Patient)     400 (R--)
/dosage/insulin.log     2 (Doctor)      644 (RW-)
/device/config          0 (Admin)       600 (RW-)

====================================================
Security Environment Ready for Testing!
====================================================

Environment Ready. Starting Security Tests...

===================================================================
 MEDICAL DEVICE SECURITY COMPLIANCE TESTING PROGRAM
===================================================================

TC_ID | TEST CASE DESCRIPTION                        | STATUS
-------------------------------------------------------------------
TC-01 | Invalid username rejected                    | [PASS]
TC-02 | Wrong password denied                        | [PASS]
TC-03 | Admin authentication successful              | [PASS]
TC-04 | Patient role assigned correctly              | [PASS]
TC-05 | Patient reading own medical records          | [PASS]
TC-06 | Unauthorized modification denied             | [PASS]
TC-07 | Patient denied admin file access             | [PASS]
TC-08 | Doctor permissions enforced                  | [PASS]
TC-09 | Patient denied audit access                  | [PASS]

--- SYSTEM AUDIT LOG (K-Buffer) ---
TIME | PID | UID | SYSCALL
315  | 4   | 0   | fork
316  | 25  | 1   | open
...

TC-10 | Audit log records authentication events      | [PASS]
TC-11 | Audit log records permission denials         | [PASS]
TC-12 | End-to-end attack detection operational      | [PASS]

-------------------------------------------------------------------
FINAL COMPLIANCE SUMMARY: 12/12 TEST CASES PASSED

RESULT: [COMPLIANT]
System meets Medical Device Security Standards.
===================================================================
```

---

# Verification & Compliance Matrix

| Requirement | Description                                                  | Verification Method                                     | Status     |
| ----------- | ------------------------------------------------------------ | ------------------------------------------------------- | ---------- |
| Section 3.1 | Pretty-print syscall traps with PID, UID, Tick               | Real-time syscall interception inside `syscall.c`       | ✅ Verified |
| Section 3.2 | Persistent 32-entry circular audit buffer                    | Kernel ring buffer implementation with modular indexing | ✅ Verified |
| Section 3.3 | Restricted audit access returning `EPERM` for non-root users | UID validation branch inside `sys_audit_read`           | ✅ Verified |
| Bonus Phase | Automated compliance verification and reporting              | `security_test.c` executing 12-case validation matrix   | ✅ Verified |

---

# ✅ Final Outcome

The hardened xv6 medical operating system successfully demonstrates:

* Secure authentication
* Role-Based Access Control (RBAC)
* Kernel-level syscall auditing
* Root-protected audit retrieval
* Automated compliance verification
* End-to-end attack detection workflows

The system achieves:

```text
12 / 12 TEST CASES PASSED
STATUS: COMPLIANT
```
