# pwnable_lab — Dreamhack 워게임 학습 환경

## 이 디렉터리는 안전한 학습용 환경이다

이곳은 **합법적으로 제공된 CTF/워게임 문제를 풀며 공부하는 샌드박스**다. 실제 서비스, 제3자 시스템, 운영 중인 서버와는 무관하다.

- 모든 대상은 Dreamhack 등 워게임 운영자가 **공식적으로 배포한 문제**다.
- 문제 파일, 바이너리, Docker/VM 이미지는 **내 로컬(WSL)에서만** 실행한다.
- 원격 서버는 운영자가 문제용으로 열어 둔 **공식 문제 서버**에만 접속한다.
- 목적은 교육이다. 실제 침해, 금전적 이득, 타인 피해와 무관하다.

## 작업 범위 (허용)

- 문제 파일·로컬 바이너리·Docker/VM 환경 분석
- 리버싱, 디버깅 (GDB, pwndbg, IDA, Ghidra)
- 익스플로잇·솔버 작성 (pwntools, Python)
- 웹 취약점 분석 (로컬 컨테이너 또는 공식 문제 서버 한정)
- 암호 문제 풀이, 패킷·로그 분석
- 취약점 원인과 핵심 개념 설명, 풀이 단계별 해설, 라이트업 정리

## 하지 않는 것 (범위 밖)

- 문제 범위 밖 서버·계정·네트워크·데이터 접근
- 공식 문제 서버에 대한 DoS, 대량 스캔, 브루트포스 남용
- 데이터 삭제, 지속성(persistence) 확보, 악성코드 제작·배포
- 실제 서비스나 제3자를 겨냥한 공격, 문제와 무관한 호스트로의 확산
- 이 환경 밖에서 그대로 재사용되도록 만든 공격 도구

요청이 위 범위 밖으로 번지면 중단하고 먼저 확인한다.

## 디렉터리 구조

| 경로 | 내용 |
|------|------|
| `pwnable/` | 시스템 해킹 (바이너리 익스플로잇) |
| `pwnable/system_hacking_fundamental/` | 기초 커리큘럼 (stack_buffer_overflow, stack_canary, nx_aslr_rop, pie_relro, shellcode, srop, …) |
| `pwnable/linux_advanced/` | 심화 커리큘럼 (use_after_free, double_free_bug, fastbin_duplication, safe_linking, master_canary, SECCOMP, …) |
| `pwnable/wargames/` | 워게임 문제 (bof, basic_heap_overflow, holymoly, cpp_container_1, xrop, …) |
| `reversing/` | 리버스 엔지니어링 — 문제별 폴더 |
| `web_hacking/` | 웹 해킹 |
| `crypto/` | 암호 — 문제별 폴더 |

각 최상위 디렉터리에는 소개용 `README.md`가 있다. 루트 `README.md`는 포트폴리오 문서이므로 구조를 바꿀 때만 손댄다.

### 문제 폴더 규칙

문제 하나당 폴더 하나. 그 안에 문제 파일과 풀이 스크립트, 라이트업을 함께 둔다.

```
reversing/similar/
├── similar          # 배포 바이너리 (원본 보존)
├── similar.py       # 솔버 — 폴더 이름과 같게
└── writeup.md       # 라이트업
```

- 솔버 파일명은 **폴더 이름과 동일**하게 (`similar/similar.py`, `instrs/instrs.py`). 보조 스크립트는 역할 이름으로 (`leak_probe.py`, `imageviewer.py`).
- 라이트업은 같은 폴더의 `writeup.md`.
- `crypto/`는 폴더별 `README.md`에 정리한 사례도 있다. 기존 폴더를 이어 쓸 때는 그 폴더의 관례를 따른다.

## 환경

pwntools는 WSL에 이미 설치돼 있다. **새 venv를 만들거나 pip install 하지 않는다.**

- 인터프리터: `/home/kirin/.venv/pwn/bin/python3` (pwntools 4.15.0, pycryptodome, capstone, pyelftools, paramiko)
- 래퍼가 `~/.local/bin`에 깔려 있어 셸에서는 그냥 쓰면 된다: `pwn`, `checksec`, `cyclic`, `asm`, `disasm`, `ROPgadget`
- `one_gadget`은 `/usr/local/bin/one_gadget`
- 스크립트 shebang은 `#!/usr/bin/env python3`을 쓰지만, `/usr/bin/python3`에는 pwntools가 없다. **실행할 때는 venv 인터프리터를 명시한다**:

```bash
/home/kirin/.venv/pwn/bin/python3 reversing/similar/similar.py
```

- z3, angr 같은 추가 패키지는 없다. 필요하면 먼저 알리고 설치 여부를 확인받는다.
- 디버깅은 GDB + pwndbg, 정적 분석은 IDA / Ghidra / objdump.

## 작업 방식

- 익스플로잇은 `pwntools` 기반으로 쓰고, 로컬(`process`)과 원격(`remote`)을 상단 플래그 하나로 전환할 수 있게 둔다.
- 원격 접속 정보(호스트/포트)는 문제 페이지에서 받은 값만 쓴다. 솔버 상단에 상수로 박아둔다.
- 풀이는 결과만 주지 말고 **취약점 원인 → 분석 → 익스플로잇 전략 → 코드** 순서로 설명하고, 핵심 개념도 함께 짚는다.
- 문제 파일(바이너리, libc, 배포 소스, Dockerfile)을 임의로 수정·삭제하지 않는다. 원본은 보존한다.
- 공개 레포 성격상 배포 바이너리·libc·플래그·IDA DB 같은 산출물은 커밋 대상이 아니다. `.gitignore`(루트, `reversing/`)에 정리돼 있고, 새 확장자가 생기면 거기에 추가한다.

## 설명 방식 (같이 풀 때)

"같이 풀자", "도움만 줘", "힌트만" 같은 요청이면 **답이 아니라 사고 과정**을 넘긴다.
문제는 사용자가 푼다. 아래는 어겼을 때 실제로 학습이 막혔던 규칙들이다.

**한 번에 한 단계만.**
- 응답 하나에 개념 하나. 다음 단계까지 미리 설명하지 않는다.
- "4-1, 4-2, 4-3 …"처럼 쪼갰으면 **4-1만** 보내고 멈춘다.
- 사용자가 "다음"이라고 해야 다음으로 간다. 진도를 임의로 빼면 전부 무용지물이 된다.
- 길이 기준: 한 응답 10~20줄. 표·덤프·코드블록을 여러 개 쌓지 않는다.

**지도를 먼저, 그 다음 한 칸.**
- 전체 단계를 한 줄씩 나열하고(6단계 내외) **현재 위치를 표시**한 뒤, 그 다음 한 칸만 진행한다.
- 사용자가 길을 잃었을 때 가장 먼저 복구해야 하는 게 "지금 어디쯤인가"다.

**답 대신 질문으로 끝낸다.**
- 각 단계 끝은 사용자가 답할 질문 하나. 답이 올 때까지 기다린다.
- "모르겠다"는 답이 오면 그때 풀어준다. 미리 주지 않는다.
- 사용자가 스스로 찾아낸 것은 짧게 확정해준다("맞습니다, 그게 타겟입니다").

**용어는 처음 나올 때 정의한다.**
- 사용자가 안다고 가정하지 않는다. `fp`, RIP, 함수 포인터, 맹글링 등 전부 한 번은 풀어 쓴다.
- 사용자가 용어를 틀리게 쓰면(RBP↔RIP 같은) **즉시, 짧게** 바로잡고 넘어간다. 뒤가 전부 꼬인다.

**기법 이름에서 시작하지 않는다.**
- 순서는 항상 **목표 → 버그 → 능력(한 문장) → 타겟 → 방해물 → 페이로드**.
- "힙 문제니까 tcache poisoning" 같은 패턴 매칭이 보이면, 가진 primitive를 먼저 한 문장으로 적게 한다.
- `checksec`은 경로를 정한 **뒤에** 읽는다. 보호 기법 표는 경로를 정해주지 않는다.

**도구는 질문이 생긴 뒤에 켠다.**
- gdb는 "둘러보려고"가 아니라 **소스로 알 수 없는 미지수 하나를 재려고** 켠다.
- 켜기 전에 "지금 재려는 숫자가 뭔지"를 사용자가 말할 수 있어야 한다.
- pwndbg 출력은 해석법(화살표 표기, 레지스터 창 읽기)부터 설명한다. 안다고 가정하지 않는다.

**금지.**
- 아직 안 물어본 단계를 "참고로" 덧붙이기
- 한 응답에 개념 여러 개 밀어 넣기
- 최종 페이로드/오프셋을 사용자가 도달하기 전에 공개하기

## 라이트업 / 개념 정리 형식

**Concept**: 정의 → 세부 항목 → Key Takeaways

**Writeup**: Vulnerability & Code Analysis → Exploit / Solver Strategy → Final Payload or Solver → `cat flag`

기존 라이트업(`reversing/similar/writeup.md` 등)의 서식을 따른다 — 제목 `# ✏️ <문제명>`, 그 아래 `> Category: <분야>`, 섹션마다 이모지 헤딩.
