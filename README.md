<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f172a,50:1e293b,100:dc2626&height=190&section=header&text=pwnable_lab&fontColor=ffffff&fontSize=52&fontAlignY=36&desc=Binary%20Exploitation%20%7C%20Reverse%20Engineering%20%7C%20Web%20Security&descAlignY=58&descSize=16" />
</p>

<p align="center">
  <a href="https://github.com/danielcho02/pwnable_lab">
    <img src="https://img.shields.io/badge/Repository-pwnable__lab-111827?style=for-the-badge&logo=github&logoColor=white" />
  </a>
  <img src="https://img.shields.io/badge/Focus-Security%20Research-dc2626?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Practice-DreamHack-2563eb?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Writeups-Active-16a34a?style=for-the-badge" />
</p>

<br>

# 🧠 pwnable_lab

> Personal security research and wargame write-up repository for  
> **binary exploitation**, **reverse engineering**, **web hacking**, and **vulnerability analysis**.

`pwnable_lab` is a personal portfolio repository where I document my security learning process through CTF-style wargames, vulnerability analysis, exploit development, and reverse engineering practice.

This repository is not only a place to store solved challenges.  
It is designed as a long-term technical archive that records how I analyze a problem, identify the root cause, build an exploit or bypass strategy, and summarize what I learned from each challenge.

<br>

---

## 🎯 Purpose

The goal of this repository is to build practical security skills through repeated analysis and documentation.

I focus on understanding the internal behavior of programs and applications rather than simply collecting final answers. Each write-up is written to explain the reasoning process behind the solution.

<br>

### Main Objectives

- Analyze vulnerabilities from source code, binaries, and runtime behavior
- Understand memory corruption and exploit mitigations at a low level
- Practice exploit development using `pwntools`, `gdb`, `pwndbg`, and related tools
- Build reverse engineering skills through static and dynamic analysis
- Study web vulnerabilities through controlled wargame environments
- Document each challenge as a reusable technical note

<br>

---

## 🧩 Study Areas

| Category | Focus |
|---|---|
| **Pwnable / System Hacking** | Memory corruption, exploit mitigations, stack layout, ROP, shellcode, binary exploitation |
| **Reverse Engineering** | Binary analysis, decompilation, algorithm recovery, encoding logic, anti-analysis concepts |
| **Web Hacking** | Input validation flaws, injection vulnerabilities, authentication bypass, server-side logic issues |
| **Write-ups** | Problem analysis, exploit strategy, payload construction, debugging notes, lessons learned |

<br>

---

## 🛠 Environment & Tools

### System Hacking / Pwnable

<p>
  <img src="https://img.shields.io/badge/Ubuntu-E95420?style=flat-square&logo=ubuntu&logoColor=white" />
  <img src="https://img.shields.io/badge/WSL-4D4D4D?style=flat-square&logo=windows-terminal&logoColor=white" />
  <img src="https://img.shields.io/badge/GDB-111827?style=flat-square" />
  <img src="https://img.shields.io/badge/pwndbg-7c3aed?style=flat-square" />
  <img src="https://img.shields.io/badge/pwntools-3776AB?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/ROPgadget-dc2626?style=flat-square" />
  <img src="https://img.shields.io/badge/checksec-0f766e?style=flat-square" />
</p>

### Reverse Engineering

<p>
  <img src="https://img.shields.io/badge/IDA%20Pro-1f2937?style=flat-square" />
  <img src="https://img.shields.io/badge/Ghidra-b91c1c?style=flat-square" />
  <img src="https://img.shields.io/badge/WinDbg-2563eb?style=flat-square" />
  <img src="https://img.shields.io/badge/x86%2Fx64%20Assembly-334155?style=flat-square" />
</p>

### Web Hacking

<p>
  <img src="https://img.shields.io/badge/Chrome%20DevTools-4285F4?style=flat-square&logo=googlechrome&logoColor=white" />
  <img src="https://img.shields.io/badge/Burp%20Suite-ff6f00?style=flat-square" />
  <img src="https://img.shields.io/badge/cURL-073551?style=flat-square" />
  <img src="https://img.shields.io/badge/HTTP-111827?style=flat-square" />
</p>

### General

<p>
  <img src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/C-00599C?style=flat-square&logo=c&logoColor=white" />
  <img src="https://img.shields.io/badge/Assembly-6b7280?style=flat-square" />
  <img src="https://img.shields.io/badge/VS%20Code-007ACC?style=flat-square&logo=visualstudiocode&logoColor=white" />
  <img src="https://img.shields.io/badge/Git-F05032?style=flat-square&logo=git&logoColor=white" />
</p>

<br>

---

## 📂 Repository Structure

```text
pwnable_lab/
├── pwnable/
│   ├── README.md
│   └── system_hacking_fundamental/
│       ├── calling_convention/
│       ├── command_injection/
│       ├── nx_aslr_rop/
│       ├── out_of_bound/
│       ├── pie_relro/
│       ├── shellcode/
│       ├── stack_buffer_overflow/
│       └── stack_canary/
│
├── reversing/
│   ├── README.md
│   ├── dungeon_in_1983/
│   ├── legacyopt/
│   ├── my_arx_cipher/
│   ├── randzzz/
│   ├── recover/
│   ├── rev_basic_7/
│   ├── rev_basic_8/
│   ├── rev_basic_9/
│   └── secret_message/
│
└── web_hacking/
    └── README.md
```

<br>

---

## 📌 Repository Direction

This repository is organized around two types of content.

<br>

### 1. Fundamental Concept Notes

The `system_hacking_fundamental` directory is used to organize basic concepts that are important for pwnable and system hacking.

These notes are not meant to be a complete lecture series.  
They are concise references that help connect individual wargame problems to core concepts such as stack canary, PIE, RELRO, NX, ASLR, shellcode, and calling convention.

<br>

### 2. Wargame Write-ups

The main focus of this repository is wargame-based practice and write-up documentation.

Each write-up aims to record:

- What the challenge gives
- What protection or constraint exists
- Where the vulnerability or key logic is located
- How the binary, program, or web application behaves
- How the exploit, bypass, or reverse calculation is constructed
- What concept should be remembered after solving the problem

<br>

---

## 🔬 Analysis Workflow

I usually solve and document challenges using the following process.

<br>

### Pwnable / System Hacking

```text
checksec
→ identify architecture and protections
→ analyze source code or disassembly
→ understand stack layout and memory behavior
→ calculate offset or leak target
→ build exploit with pwntools
→ verify with local and remote execution
→ summarize the core vulnerability
```

<br>

### Reverse Engineering

```text
inspect binary
→ analyze strings, functions, and control flow
→ decompile and rename important variables
→ identify validation or encoding logic
→ recover constants and transformation rules
→ write a solver script
→ verify the recovered result
→ document the reversing strategy
```

<br>

### Web Hacking

```text
review source code or request flow
→ identify user-controlled input
→ analyze filtering and validation logic
→ test payload behavior
→ bypass constraints
→ confirm impact
→ document root cause and mitigation
```

<br>

---

## 🧾 Write-up Format

Write-ups may vary depending on the challenge, but most notes follow this structure.

```md
# ✏️ Challenge Name Write-up

## 1. Challenge Overview

## 2. File / Source Analysis

## 3. Vulnerability or Key Logic

## 4. Exploit / Solver Strategy

## 5. Final Payload or Solver

## 6. Key Takeaways
```

For concept notes, I use a simpler format.

```md
# 🧠 Concept: Concept Name <br>

## 📌 Definition <br>

### 📄 Concept Analysis <br>

### 🧪 Observation <br>

### ⚔️ Exploitation / Usage <br>

### ✅ Key Takeaways <br>
```

<br>

---

## 📚 Learning Platform

Most of the practice problems and lectures are based on DreamHack.

| Platform | Purpose |
|---|---|
| [DreamHack - System Hacking Fundamental](https://dreamhack.io/lecture/paths/system-hacking-fundamental) | Basic pwnable and system hacking concepts |
| [DreamHack - Reverse Engineering Fundamental](https://dreamhack.io/lecture/paths/reverse-engineering-fundamental) | Reverse engineering fundamentals and practice |
| [DreamHack - Web Hacking Fundamental](https://dreamhack.io/lecture/paths/web-hacking-fundamental) | Web vulnerability fundamentals and practice |

<br>

---

## 🧠 What I Try to Learn from Each Problem

A solved challenge is meaningful only when the underlying idea becomes reusable.

For each problem, I try to answer the following questions:

```text
What is the bug or hidden logic?
Why does it happen?
Which assumption is broken?
What information do I need to leak or recover?
How does the payload or solver work?
What would prevent this vulnerability?
What should I remember for the next problem?
```

<br>

---

## 🛡️ Ethics

All content in this repository is for **legal security research, CTF practice, and educational purposes only**.

The purpose of this repository is to study vulnerabilities in controlled environments, improve analysis skills, and develop a stronger understanding of defensive security.

<br>

---

## 📈 Progress Mindset

> Exploitation is not about memorizing payloads.  
> It is about understanding how assumptions fail.

<br>

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:dc2626,50:1e293b,100:0f172a&height=120&section=footer" />
</p>
