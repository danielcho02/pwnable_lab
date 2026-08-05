# 🧠 Memory Corruption: Stack Buffer Overflow

## 📌 Definition
Buffer: 데이터가 목적지로 이동되기 전에 보관되는 임시 저장소<br>
Stack Buffer: Stack에 있는 지역 변수<br>
Heap Buffer: Heap에 할당된 메모리 영역<br>
Buffer Overflow: Buffer가 넘치는 것<br>

### 📄 Important Data Tampering
Buffer Overflow가 발생하는 Buffer 뒤에 중요한 데이터가 있다면 해당 데이터가 변조 됨으로써 문제 발생 가능<br>

```c
// Name: sbof_auth.c
// Compile: gcc -o sbof_auth sbof_auth.c -fno-stack-protector
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "prob.h"
char secret_passwd[16] = {0, };
int main() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    get_random_string(secret_passwd, 15);
    int auth = 0;
    char password[16] = {0, };
    printf("Enter the password: ");
    scanf("%255s", password);
    if(!strncmp(password, secret_passwd, 15))
        auth = 1;
    if(auth == 1) {
        printf("Access granted!\n");
    } else {
        printf("Access denied...\n");
    }
}
```

auth를 '1'로 변경해야 함 <br>
password = 16 byte<br>
password와 auth의 거리(padding) = 12byte -> 메모리 주소의 차로 확인<br>
scanf()에서 buffer overflow가 가능하므로 auth의 값을 임의로 변경 가능<br>
payload = password + padding = A*28 + \x01\x00\x00\x00을 입력 (little endian)<br>


### 📄 Data Leakage
C언어 표준 문자열 null byte로 종결<br>
Buffer overflow로 null byte를 모두 제거 ->  다른 버퍼의 데이터도 같이 출력 가능<br>

```c
// Name: sbof_leak.c
// Compile: gcc -o sbof_leak sbof_leak.c -fno-stack-protector
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "prob.h"

int main(void) {

    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    struct {
        char name[8];
        char barrier[4];
        char secret[16];
    } s;

    get_random_string(s.secret, 15);

    printf("Your name: ");
    read(0, s.name, 12);
    printf("Your name is %s.", s.name);
}
```

read(0, s.name, 12);에서 s.name의 변수의 크기는 8byte이지만 12byte를 입력 받고 있으므로 <br>
s.name의 시작부터 12바이트를 모두 \x00이 아닌 값으로 채우면 s.secret을 함께 출력함<br>


### 📄 Manipulating Execution Flow
함수 호출 규약에서 함수를 호출할 떄 반환 주소를 스택에 쌓고 반환될 때 이를 꺼내어 원래의 실행흐름으로 돌아감<br>
Return Adress를 조작하면 프로세스 실행 흐름을 바꿀 수 있음<br>

```c
// Name: sbof_ret_overwrite.c
// Compile: gcc -o sbof_ret_overwrite sbof_ret_overwrite.c -fno-stack-protector
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int you_cant_call_me(void) {
    puts("What?\n");
    puts("How did you get here?\n");
    return 0;
}

int main(void) {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    
    char buf[8];
    printf("Overwrite: ");
    read(0, buf, 0x100);
    return 0;
}
```

buf의 주소는 0x7fff0000ffe8이고 ret의 주소는 0x7fff0000fff8이므로 16byte 차이가 남<br>
ret값을 0xdeadbeef로 바꾸기 위해서는 A를 16개 입력 후 \xef\xbe\xad\xde\x00\x00\x00\x00를 입력<br>
you_cant_call_me의 주소를 메모리 영역에서 찾아 같은 방법으로 입력하면 What?과 How did you get here?이라는 문구가 터미널에 출력됨<br>
