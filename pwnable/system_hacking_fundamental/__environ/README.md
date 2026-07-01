# ✏️ __environ
https://dreamhack.io/wargame/challenges/363/

## 📄 Vulnerability & Code Analysis
프로세스는 환경 변수 정보를 저장하고 필요할 때마다 불러와 사용
환경 변수 = 매번 변할 수 있는 동적인 값들의 모임, 시스템의 정보를 갖고 있는 변수
사용자가 직접 추가 및 수정하거나 삭제할 수 없음

리눅스에서 제공하는 명령어들은 `/bin`, `/usr/bin`등의 디렉터리에 위치
명령어 입력 시 환경 변수에 명시된 디렉터리에서 명령어를 탐색하고 실행하기 때문에 명령어의 경로를 직접 입력 X
터미널 뿐만 아니라 프로그램에서도 프로세스를 로드하면서 환경 변수 초기화
환경 변수에 대한 정보는 `STACK` 영역에 존재
라이브러리 함수를 실행할 때 해당 정보를 참조하기 때문에 환경 변수를 가리키는 포인터 별도 선언
```bash
(.venv) (base) ➜  __environ readelf -s ./libc.so.6 | grep "environ"
   133: 0000000000221200     8 OBJECT  WEAK   DEFAULT   35 _environ@@GLIBC_2.2.5
   958: 0000000000221200     8 OBJECT  WEAK   DEFAULT   35 environ@@GLIBC_2.2.5
```


```c
// Name: environ.c
// Compile: gcc -o environ environ.c

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

void sig_handle() {
  exit(0);
}
void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  signal(SIGALRM, sig_handle);
  alarm(5);
}

void read_file() {
  char file_buf[4096];

  int fd = open("./flag", O_RDONLY);
  read(fd, file_buf, sizeof(file_buf) - 1);
  close(fd);
}
int main() {
  char buf[1024];
  long addr;
  int idx;

  init();
  read_file();

  printf("stdout: %p\n", stdout);

  while (1) {
    printf("> ");
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        printf("Addr: ");
        scanf("%ld", &addr);
        printf("%s", (char *)addr);
        break;
      default:
        break;
    }
  }
  return 0;
}

```

## 🗡️ Exploit / Solver Strategy

## 💻 Final Payload or Solver

## 🏳️ cat flag
  
