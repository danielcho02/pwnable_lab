# 🧠 Concept: Out of Bounds <br>

## 📌 Background <br>
Out of Bounds(OOB)는 배열이나 버퍼를 참조할 때, 인덱스가 정상 범위를 벗어나는 취약점이다. <br>

배열의 길이가 4라면 정상 인덱스는 보통 `0 ~ 3`이다. <br>
그런데 사용자가 `-1`, `4`, `5` 같은 값을 넣을 수 있고, 프로그램이 이를 제대로 검사하지 않으면 배열 밖의 메모리를 참조하게 된다. <br>

즉, OOB는 다음과 같은 상황에서 발생한다. <br>

1. 사용자가 배열 인덱스 값을 직접 입력할 수 있음 <br>
2. 프로그램이 인덱스 범위를 정확히 검사하지 않음 <br>
3. 배열 밖에 있는 메모리 값을 읽거나 쓸 수 있음 <br>

배열의 범위를 벗어나는 참조를 이용하면, 배열 근처에 있는 다른 변수의 값을 읽거나 조작할 수 있다. <br>


## 📄 OOB Read <br>
OOB Read는 배열 밖의 메모리를 읽는 취약점이다. <br>

아래 예제에서는 `docs` 배열의 범위를 벗어나 `secret_code`가 가리키는 값을 읽을 수 있다. <br>

```c
// Name: oob_read.c
// Compile: gcc -o oob_read oob_read.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char secret[256];

int read_secret() {
  FILE *fp;

  if ((fp = fopen("secret.txt", "r")) == NULL) {
    fprintf(stderr, "`secret.txt` does not exist");
    return -1;
  }

  fgets(secret, sizeof(secret), fp);
  fclose(fp);

  return 0;
}

int main() {
  char *docs[] = {"COMPANY INFORMATION", "MEMBER LIST", "MEMBER SALARY",
                  "COMMUNITY"};
  char *secret_code = secret;
  int idx;

  if (read_secret() != 0) {
    exit(-1);
  }

  puts("What do you want to read?");
  for (int i = 0; i < 4; i++) {
    printf("%d. %s\n", i + 1, docs[i]);
  }
  printf("> ");
  scanf("%d", &idx);

  if (idx > 4) {
    printf("Detect out-of-bounds");
    exit(-1);
  }

  puts(docs[idx - 1]);
  return 0;
}
```

핵심 코드는 아래 부분이다. <br>

```c
if (idx > 4) {
  printf("Detect out-of-bounds");
  exit(-1);
}

puts(docs[idx - 1]);
```

여기서 프로그램은 `idx > 4`만 검사한다. <br>
즉, `idx`가 `0`이거나 음수인 경우는 막지 못한다. <br>

정상적인 입력은 `1 ~ 4`이다. <br>

```c
idx = 1 -> docs[0]
idx = 2 -> docs[1]
idx = 3 -> docs[2]
idx = 4 -> docs[3]
```

하지만 `idx = 0`을 입력하면 다음과 같이 계산된다. <br>

```c
idx = 0
docs[idx - 1] = docs[-1]
```

`docs[-1]`은 `docs` 배열의 첫 번째 원소보다 앞쪽에 있는 메모리를 참조한다. <br>
이때 해당 위치에 `secret_code`가 존재하면, `puts(docs[-1])`는 `secret_code`가 가리키는 `secret` 값을 출력하게 된다. <br>


## 🧪 Example <br>

```bash
$ echo "THIS IS SECRET" > ./secret.txt
$ ./oob_read
What do you want to read?
1. COMPANY INFORMATION
2. MEMBER LIST
3. MEMBER SALARY
4. COMMUNITY
> 0
THIS IS SECRET
```

`idx`에 `0`을 입력했기 때문에 `docs[-1]`이 참조된다. <br>
그 결과 `docs` 배열 밖에 있는 `secret_code`를 읽게 되고, `secret.txt`의 내용이 출력된다. <br>


## 📌 Key Point <br>
OOB 취약점의 핵심은 배열 인덱스 검증이 불완전하다는 것이다. <br>

이 예제에서는 상한 검사만 존재한다. <br>

```c
if (idx > 4)
```

하지만 하한 검사가 없다. <br>

```c
idx < 1
```

따라서 `idx = 0` 또는 음수 입력을 통해 배열 앞쪽 메모리에 접근할 수 있다. <br>


## 🛡️ Prevention <br>
OOB를 막으려면 배열 인덱스의 하한과 상한을 모두 검사해야 한다. <br>

```c
if (idx < 1 || idx > 4) {
  printf("Detect out-of-bounds");
  exit(-1);
}
```

이렇게 검사하면 `idx`가 `1 ~ 4` 범위 안에 있을 때만 배열을 참조하게 된다. <br>

즉, 안전한 배열 접근 조건은 다음과 같다. <br>

```c
1 <= idx <= 4
```

배열을 사용할 때는 항상 사용자가 입력한 인덱스가 정상 범위 안에 있는지 확인해야 한다. <br>
상한만 검사하거나 하한만 검사하면 OOB 취약점이 발생할 수 있다. <br>
뿐만 아니라 임의 주소에 값을 쓰는 것도 가능하다.



