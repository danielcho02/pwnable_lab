# ✏️ Secure Mail
https://dreamhack.io/wargame/challenges/92

## 📄 Vulnerability & Code Analysis

이 문제는 HTML 내부의 JavaScript가 사용자의 6자리 생일을 입력받아,
암호화된 이미지를 복호화하는 구조이다.

입력창에는 다음과 같은 힌트가 존재한다.

```html
<input
    id="pass"
    type="password"
    maxlength="6"
    placeholder="Input your birthday eg.) 850810"
>

<button
    type="submit"
    onclick="_0x9a220(pass.value);"
>
    Confirm
</button>
```

따라서 입력값은 다음 형식임을 알 수 있다.

```text
YYMMDD
```

Confirm 버튼을 누르면 다음 함수가 호출된다.

```javascript
_0x9a220(pass.value);
```

즉, `_0x9a220` 함수가 사용자의 입력값을 처리하는 핵심 함수이다.

---

### 원본 핵심 코드

원본 코드는 대부분 한 줄로 붙어 있으며,
핵심 부분만 보기 좋게 정리하면 다음과 같다.

```javascript
function _0x9a220(_0x30bf04) {
    var _0x540d50 = _0x225843,

        _0x2ee89c =
            Array[
                _0x540d50('0x99', '3itY')
            ](
                _0x3eebe5(
                    _0x30bf04,
                    null,
                    raw = !![]
                )
            )[
                _0x540d50('0xe2', 'G(su')
            ](
                _0x66324e =>
                    _0x66324e['charCodeAt']()
            ),

        _0x2fef58 =
            new _0x58829a['_0x14c3a3'][
                _0x540d50('0x29', 'd%09')
            ](
                _0x2ee89c,
                _0x2ee89c
            );

    file = [
        0x68, 0xda, 0xe1, 0x1b,
        0x20, 0x6e, 0xbc, 0x1f,
        0x01, 0xff, 0x6f, 0x04,
        0x89, 0x8a, 0x6e, 0x1d,

        // 이하 암호문 배열 생략
    ];

    dfbora =
        _0x2fef58['decrypt'](
            file
        );

    // 복호화된 바이트를 문자열로 변환
    // MD5 검증
    // document.write로 이미지 출력
}
```

이 코드를 그대로 읽기 어렵기 때문에
먼저 문자열 난독화 구조를 확인하였다.

---

### 문자열 난독화 구조

코드 상단에는 매우 많은 문자열이 들어 있는 배열이 존재한다.

```javascript
var _0x2297 = [
    'W7OkEmokW5OKfGar',
    'pfHcWP/cS8oTWPFcJNi=',
    'EsxdHSkRFgevzcO=',
    ...
];
```

이 배열에는 `"from"`, `"map"`, `"length"`와 같은 실제 문자열이
그대로 저장되어 있지 않다.

원래 문자열은 다음과 같은 형태로 변형되어 저장되어 있다.

```text
원래 문자열
    ↓
RC4 처리
    ↓
Base64 인코딩
    ↓
_0x2297 배열에 저장
```

프로그램이 실행될 때는 반대로 처리한다.

```text
_0x2297 배열 값
    ↓
Base64 디코딩
    ↓
RC4 복호화
    ↓
원래 문자열 반환
```

---

### 배열 회전

문자열 배열 아래에는 다음 코드가 존재한다.

```javascript
(function (_0x35fa1a, _0x2297e4) {
    var _0x2439b6 = function (_0x27e6d1) {
        while (--_0x27e6d1) {
            _0x35fa1a['push'](
                _0x35fa1a['shift']()
            );
        }
    };

    _0x2439b6(++_0x2297e4);

}(_0x2297, 0x1c4));
```

핵심 연산은 다음과 같다.

```javascript
array.push(
    array.shift()
);
```

`shift()`는 배열의 첫 번째 값을 제거하고,
`push()`는 그 값을 배열의 마지막에 추가한다.

예를 들어 다음 배열이 있다고 가정한다.

```javascript
["A", "B", "C", "D"]
```

한 번 회전하면 다음과 같이 된다.

```javascript
["B", "C", "D", "A"]
```

두 번 회전하면 다음과 같이 된다.

```javascript
["C", "D", "A", "B"]
```

이 문제에서는 배열을 452번 회전한다.

따라서 원본 배열의 인덱스를 그대로 확인하면
실제 실행 시 참조되는 문자열과 위치가 달라진다.

---

### `_0x2439` 문자열 디코더

배열 회전 이후 `_0x2439` 함수가 정의된다.

원본 코드는 복잡하지만 역할을 단순화하면 다음과 같다.

```javascript
function decodeString(
    index,
    key
) {
    index = Number(index);

    const encoded =
        rotatedStringTable[index];

    const decoded =
        base64Decode(encoded);

    const plaintext =
        rc4Decrypt(
            decoded,
            key
        );

    return plaintext;
}
```

실제 함수 이름은 다음과 같다.

```javascript
_0x2439
```

호출 형태는 다음과 같다.

```javascript
_0x2439(
    '0x99',
    '3itY'
)
```

두 인자의 의미는 다음과 같다.

```text
첫 번째 인자: 회전된 문자열 배열의 인덱스
두 번째 인자: RC4 복호화 키
```

---

### 디코더가 Base64와 RC4인 이유

`_0x2439` 내부의 `_0x27e6d1` 함수에는
다음 문자열이 존재한다.

```javascript
'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/='
```

이는 Base64 문자표이다.

따라서 `_0x27e6d1`은 Base64 디코더임을 알 수 있다.

또한 `_0x52c29f` 함수는 다음 구조를 가진다.

```javascript
for (let i = 0; i < 256; i++) {
    S[i] = i;
}
```

이후 키를 이용하여 배열을 섞는다.

```javascript
for (let i = 0; i < 256; i++) {
    j = (
        j +
        S[i] +
        key.charCodeAt(
            i % key.length
        )
    ) % 256;

    [S[i], S[j]] =
        [S[j], S[i]];
}
```

마지막으로 입력 바이트와 키스트림을 XOR한다.

```javascript
output += String.fromCharCode(
    inputByte ^
    keyStreamByte
);
```

이 구조는 RC4의 KSA와 PRGA 동작과 일치한다.

따라서 `_0x2439`는 다음 순서로 문자열을 복원한다.

```text
1. 배열 인덱스로 값 선택
2. Base64 디코딩
3. 두 번째 인자를 키로 RC4 복호화
4. 실제 문자열 반환
```

---

### 디코더는 새로 만든 것이 아니라 원본을 직접 실행

문자열 디코더를 별도로 다시 구현한 것이 아니다.

HTML이 로드되면 원본에 포함된 `_0x2439` 함수도 함께 실행되므로,
브라우저 Console에서 원본 디코더를 직접 호출할 수 있다.

코드에는 다음과 같은 별칭이 존재한다.

```javascript
var _0x225843 =
    _0x2439;
```

그리고 `_0x9a220` 함수 안에서는 다시 다음 별칭을 사용한다.

```javascript
var _0x540d50 =
    _0x225843;
```

따라서 다음 세 이름은 모두 같은 디코더를 가리킨다.

```text
_0x2439
=
_0x225843
=
_0x540d50
```

브라우저에서 HTML 파일을 연 뒤
F12의 Console 탭에서 다음을 실행하면 된다.

```javascript
_0x225843(
    '0x99',
    '3itY'
)
```

출력:

```text
from
```

다음 호출을 실행한다.

```javascript
_0x225843(
    '0xe2',
    'G(su'
)
```

출력:

```text
map
```

여러 개를 한 번에 확인할 수도 있다.

```javascript
[
    _0x225843(
        '0x99',
        '3itY'
    ),

    _0x225843(
        '0xe2',
        'G(su'
    ),

    _0x225843(
        '0x29',
        'd%09'
    )
]
```

즉 디코더의 결과는 추측한 것이 아니라,
원본에 포함된 문자열 테이블과 디코더를 그대로 실행하여 확인하였다.

---

### 원본 표현 변환

원본에는 다음 코드가 존재한다.

```javascript
Array[
    _0x540d50(
        '0x99',
        '3itY'
    )
]
```

디코더 결과는 다음과 같다.

```text
_0x540d50('0x99', '3itY')
→ "from"
```

따라서 코드는 다음과 같이 바뀐다.

```javascript
Array[
    "from"
]
```

JavaScript에서 다음 두 표현은 같은 의미이다.

```javascript
Array["from"]
```

```javascript
Array.from
```

마찬가지로 다음 표현을 확인한다.

```javascript
[
    _0x540d50(
        '0xe2',
        'G(su'
    )
]
```

디코더 결과:

```text
_0x540d50('0xe2', 'G(su')
→ "map"
```

따라서 다음과 같이 바뀐다.

```javascript
["map"]
```

점 표기법으로 바꾸면 다음과 같다.

```javascript
.map
```

---

### 핵심 코드 변환 과정

원본 코드:

```javascript
_0x2ee89c =
    Array[
        _0x540d50(
            '0x99',
            '3itY'
        )
    ](
        _0x3eebe5(
            _0x30bf04,
            null,
            raw = !![]
        )
    )[
        _0x540d50(
            '0xe2',
            'G(su'
        )
    ](
        _0x66324e =>
            _0x66324e[
                'charCodeAt'
            ]()
    );
```

문자열 디코더 결과를 대입하면 다음과 같다.

```javascript
_0x2ee89c =
    Array["from"](
        _0x3eebe5(
            _0x30bf04,
            null,
            true
        )
    )["map"](
        _0x66324e =>
            _0x66324e.charCodeAt()
    );
```

점 표기법으로 정리하면 다음과 같다.

```javascript
_0x2ee89c =
    Array.from(
        _0x3eebe5(
            _0x30bf04,
            null,
            true
        )
    ).map(
        _0x66324e =>
            _0x66324e.charCodeAt()
    );
```

변수명을 역할에 맞게 바꾸면 다음과 같이 해석할 수 있다.

```javascript
digestBytes =
    Array.from(
        hashFunction(
            password,
            null,
            true
        )
    ).map(
        character =>
            character.charCodeAt()
    );
```

여기까지가 문자열 난독화를 실제 값으로 치환한 과정이다.

---

### `!![]`의 의미

원본에는 다음 표현이 존재한다.

```javascript
raw = !![]
```

JavaScript에서 빈 배열은 truthy 값이다.

```javascript
Boolean([])
```

결과:

```javascript
true
```

따라서:

```javascript
![]
```

는 `false`이고,

```javascript
!![]
```

는 `true`이다.

결국 다음 호출은:

```javascript
_0x3eebe5(
    password,
    null,
    raw = !![]
)
```

다음과 같은 의미이다.

```javascript
_0x3eebe5(
    password,
    null,
    true
)
```

---

### 식별자 난독화

문자열 디코더를 실행해도 다음 이름들은 그대로 남는다.

```text
_0x3eebe5
_0x2ee89c
_0x2fef58
dfbora
```

이 이름들은 암호화된 문자열이 아니라,
난독화 과정에서 무작위 이름으로 변경된 함수명과 변수명이다.

따라서 원래 이름 자체를 복구할 수는 없다.

대신 함수의 입력값, 출력값, 내부 상수,
호출 위치를 분석하여 의미 있는 이름으로 다시 붙인다.

```text
_0x3eebe5
→ MD5 관련 함수

_0x2ee89c
→ MD5 결과 16바이트

_0x2fef58
→ AES-CBC 객체

file
→ ciphertext

dfbora
→ decryptedBytes
```

즉 원래 이름을 되살린 것이 아니라,
동작을 보고 사람이 의미 있는 이름으로 재명명한 것이다.

---

### `_0x3eebe5`가 MD5인 이유

`_0x9a220` 함수에서 사용자 입력은 다음 함수로 전달된다.

```javascript
_0x3eebe5(
    _0x30bf04,
    null,
    true
)
```

`_0x3eebe5` 함수는 다음과 같다.

```javascript
function _0x3eebe5(
    _0x2c5c24,
    _0xceb417,
    _0x169ee3
) {
    if (!_0xceb417) {
        if (!_0x169ee3)
            return _0x42115c(
                _0x2c5c24
            );

        return _0x4cd335(
            _0x2c5c24
        );
    }

    if (!_0x169ee3)
        return _0x4fb15f(
            _0xceb417,
            _0x2c5c24
        );

    return _0x2f5ed0(
        _0xceb417,
        _0x2c5c24
    );
}
```

분기 구조를 정리하면 다음과 같다.

| HMAC Key | Raw 출력 | 호출 함수 | 의미 |
|---|---:|---|---|
| 없음 | false | `_0x42115c` | Hex MD5 |
| 없음 | true | `_0x4cd335` | Raw MD5 |
| 있음 | false | `_0x4fb15f` | Hex HMAC-MD5 |
| 있음 | true | `_0x2f5ed0` | Raw HMAC-MD5 |

현재 호출은 다음과 같다.

```javascript
_0x3eebe5(
    password,
    null,
    true
)
```

두 번째 인자가 `null`이므로 HMAC이 아닌 일반 해시를 사용하고,
세 번째 인자가 `true`이므로 16진수 문자열이 아닌 raw 결과를 반환한다.

즉 다음과 같다.

```text
raw MD5(password)
```

---

### MD5 구현 확인

내부 함수 `_0x1bb977`에는 다음 초기값이 존재한다.

```javascript
0x67452301
-0x10325477
-0x67452302
0x10325476
```

JavaScript signed 32비트 값을
unsigned 값으로 표현하면 다음과 같다.

```text
0x67452301
0xefcdab89
0x98badcfe
0x10325476
```

이 값들은 MD5 알고리즘의 초기 레지스터 값과 정확히 일치한다.

또한 내부에는 다음 네 함수가 존재한다.

```text
_0x3170e2
_0x55dc4e
_0x182ec0
_0x5527b8
```

내부 연산은 각각 다음 MD5 라운드 함수와 일치한다.

```text
F(X, Y, Z) = (X & Y) | (~X & Z)
G(X, Y, Z) = (X & Z) | (Y & ~Z)
H(X, Y, Z) = X ^ Y ^ Z
I(X, Y, Z) = Y ^ (X | ~Z)
```

따라서 `_0x3eebe5`는 MD5와 HMAC-MD5를 감싸는 래퍼 함수임을 확인할 수 있다.

---

### MD5 결과를 바이트 배열로 변환

`_0x3eebe5`는 raw MD5 결과를
JavaScript binary string 형태로 반환한다.

```javascript
rawDigest =
    _0x3eebe5(
        password,
        null,
        true
    );
```

이 문자열의 각 문자를 `charCodeAt()`으로 변환한다.

```javascript
digestBytes =
    Array.from(
        rawDigest
    ).map(
        character =>
            character.charCodeAt()
    );
```

결과는 다음 형태의 16바이트 배열이다.

```text
[
    MD5 byte 0,
    MD5 byte 1,
    ...
    MD5 byte 15
]
```

이 값이 `_0x2ee89c`에 저장된다.

---

### AES-CBC 확인

`_0x9a220` 내부에서는 다음 생성자가 호출된다.

```javascript
new _0x58829a['_0x14c3a3'][
    _0x540d50(
        '0x29',
        'd%09'
    )
](
    _0x2ee89c,
    _0x2ee89c
);
```

문자열 디코더 결과로 선택된 프로퍼티는
AES mode 객체 내부의 CBC 생성자로 연결된다.

해당 생성자 `_0x2ef5df` 내부에는
다음 문자열이 직접 존재한다.

```javascript
'Cipher Block Chaining'
```

또한 생성자 내부에서 첫 번째 인자는 AES key로 사용되고,
두 번째 인자는 IV로 저장된다.

의미 있는 이름으로 바꾸면 다음과 같다.

```javascript
function CBC(
    key,
    iv
) {
    this.iv = iv;
    this.aes = new AES(key);
}
```

`_0x9a220`에서는 같은 `_0x2ee89c` 값을 두 번 전달한다.

```javascript
new CBC(
    _0x2ee89c,
    _0x2ee89c
)
```

따라서 실제 설정은 다음과 같다.

```text
AES key = MD5(password)
AES IV  = MD5(password)
Mode    = CBC
```

---

### 암호문 확인

함수 내부에는 매우 긴 바이트 배열이 존재한다.

```javascript
file = [
    0x68, 0xda, 0xe1, 0x1b,
    0x20, 0x6e, 0xbc, 0x1f,
    ...
];
```

이 배열은 바로 다음 코드에 전달된다.

```javascript
dfbora =
    _0x2fef58[
        'decrypt'
    ](
        file
    );
```

따라서 `file`은 AES-CBC 암호문이고,
`dfbora`는 복호화된 바이트 배열이다.

의미 있는 이름으로 바꾸면 다음과 같다.

```javascript
decryptedBytes =
    aesCbc.decrypt(
        ciphertext
    );
```

복호화된 바이트는 문자열로 변환된다.

```javascript
plaintext = "";

for (
    let i = 0;
    i < decryptedBytes.length;
    i++
) {
    plaintext +=
        String.fromCharCode(
            decryptedBytes[i]
        );
}
```

정상적으로 복호화된 평문은 다음 형식으로 시작한다.

```text
data:image/png;base64,
```

마지막으로 평문을 이미지의 `src` 속성으로 사용한다.

```javascript
document.write(
    '<img src="' +
    plaintext +
    '">'
);
```

---

### 복원된 전체 로직

난독화 문자열을 실제 값으로 치환하고,
함수와 변수의 역할을 기준으로 이름을 다시 붙이면
핵심 로직은 다음과 같다.

```javascript
function checkPassword(
    password
) {
    const rawDigest =
        rawMD5(
            password
        );

    const key =
        Array.from(
            rawDigest
        ).map(
            character =>
                character.charCodeAt()
        );

    const aesCbc =
        new CBC(
            key,
            key
        );

    const ciphertext = [
        0x68,
        0xda,
        0xe1,
        0x1b,
        ...
    ];

    const decryptedBytes =
        aesCbc.decrypt(
            ciphertext
        );

    let plaintext = "";

    for (
        const byte
        of decryptedBytes
    ) {
        plaintext +=
            String.fromCharCode(
                byte
            );
    }

    document.write(
        '<img src="' +
        plaintext +
        '">'
    );
}
```

```text
숨겨진 문자열
→ 원본 디코더 실행으로 실제 값 확인

난독화된 변수명과 함수명
→ 내부 동작과 호출 흐름을 보고 의미 있는 이름으로 재명명
```

---

### 취약점

이 문제의 핵심 취약점은 암호화 알고리즘 자체보다
매우 작은 비밀번호 공간과 클라이언트 측 검증 구조에 있다.

입력값은 6자리 생일이다.

```text
YYMMDD
```

가능한 모든 숫자를 검사하더라도 최대 경우의 수는 다음과 같다.

```text
000000 ~ 999999
```

즉 최대 1,000,000개이다.

실제 날짜만 생성하면 약 36,500개 정도만 검사하면 된다.

또한 다음 정보가 모두 클라이언트에 노출되어 있다.

```text
암호화 알고리즘
암호문
키 생성 방식
IV 생성 방식
평문 형식
```

키 생성 방식도 다음처럼 단순하다.

```text
key = MD5(6자리 생일)
```

MD5에는 salt가 없으며,
AES key와 IV가 동일한 값이다.

따라서 서버와 통신하지 않고도
완전한 오프라인 브루트포싱이 가능하다.

보안상 문제점을 정리하면 다음과 같다.

```text
1. 비밀번호 공간이 매우 작음
2. MD5에 salt가 없음
3. AES key와 IV가 동일함
4. 암호문이 클라이언트에 그대로 포함됨
5. 복호화 평문의 시작 문자열을 예측할 수 있음
6. 모든 검증이 클라이언트 측에서 수행됨
```

## 🗡️ Exploit / Solver Strategy

전체 암호문은 매우 크다. 모든 비밀번호 후보마다 전체 암호문을 복호화하면 비효율적이다.

하지만 AES-CBC의 첫 번째 평문 블록은 첫 번째 암호문 블록과 IV만으로 복호화할 수 있다.

AES-CBC 첫 번째 블록 복호화는 다음과 같다.

```text
P1 = AES_DEC(Key, C1) XOR IV
```

정상 평문의 시작은 다음과 같다.

```text
data:image/png;base64,
```

AES 블록 크기는 16바이트이므로 첫 번째 블록은 정확히 다음 문자열이다.

```text
data:image/png;b
```

따라서 각 후보마다 전체 파일을 복호화할 필요 없이, 암호문의 첫 16바이트만 복호화하면 된다.

브루트포싱 과정은 다음과 같다.

```text
1. YYMMDD 형식의 생일 후보 생성
2. MD5(candidate) 계산
3. MD5 값을 AES key로 사용
4. MD5 값을 AES IV로 사용
5. 암호문의 첫 16바이트만 복호화
6. 결과가 "data:image/png;b"인지 비교
7. 일치하면 정답 후보로 판단
8. 해당 key로 전체 암호문 복호화
9. PKCS#7 padding 제거
10. data:image/png;base64, 부분 제거
11. Base64 디코딩
12. PNG 파일로 저장
```

이 방식은 후보 하나당 AES 블록 하나만 처리하므로 매우 빠르다.


## 💻 Final Payload or Solver

필요한 패키지를 설치한다.

```bash
pip install pycryptodome
```

최종 솔버는 다음과 같다.

```python
from pathlib import Path
from datetime import date, timedelta
from hashlib import md5
from base64 import b64decode
import re

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


html = Path(
    "secure-mail.html"
).read_text(
    encoding="utf-8",
    errors="ignore"
)

array = re.search(
    r"file\s*=\s*\[(.*?)\]\s*,\s*dfbora",
    html,
    re.S
).group(1)

ciphertext = bytes(
    int(value, 0)
    for value in re.findall(
        r"0x[0-9a-fA-F]+|\d+",
        array
    )
)


current = date(2000, 1, 1)
end = date(2100, 1, 1)

while current < end:
    password = current.strftime(
        "%y%m%d"
    )

    key = md5(
        password.encode()
    ).digest()

    first_block = AES.new(
        key,
        AES.MODE_CBC,
        iv=key
    ).decrypt(
        ciphertext[:16]
    )

    if first_block == b"data:image/png;b":
        break

    current += timedelta(days=1)


plaintext = AES.new(
    key,
    AES.MODE_CBC,
    iv=key
).decrypt(
    ciphertext
)

plaintext = unpad(
    plaintext,
    AES.block_size
)

encoded_image = plaintext.split(
    b",",
    1
)[1]

image = b64decode(
    encoded_image
)

Path(
    "decrypted.png"
).write_bytes(
    image
)

print(password)
```

실행한다.

```bash
python3 secure_mail.py
```

실행 결과로 올바른 6자리 생일이 출력된다.

```text
[6자리 생일]
```

동시에 현재 디렉터리에 다음 파일이 생성된다.

```text
decrypted.png
```

해당 이미지를 열면 문제의 결과를 확인할 수 있다.

전체 풀이 흐름을 요약하면 다음과 같다.

```text
HTML 버튼 확인
        ↓
onclick 함수 확인
        ↓
_0x9a220 추적
        ↓
문자열 디코더 구조 확인
        ↓
_0x3eebe5 = raw MD5 확인
        ↓
AES-CBC key = MD5(password)
AES-CBC IV  = MD5(password)
        ↓
file 배열 = 암호문
        ↓
YYMMDD 브루트포싱
        ↓
첫 블록 known plaintext 검사
        ↓
전체 복호화
        ↓
Base64 PNG 저장
```


## 🏳️ cat flag
<img width="1189" height="668" alt="decrypted" src="https://github.com/user-attachments/assets/db1db4ee-cf3a-4d4e-94e1-d4b75765ec18" />

