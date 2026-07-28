# ✏️ Secure Mail
https://dreamhack.io/wargame/challenges/92

## 📄 Vulnerability & Code Analysis

이 문제는 HTML 내부에 포함된 JavaScript가 사용자의 6자리 생일을 입력받아 암호화된 이미지를 복호화하는 구조이다.

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

### JavaScript 코드 분리

HTML 전체를 분석해도 되지만, `<script>` 태그 내부만 따로 추출하면 더 편하게 볼 수 있다.

```bash
python3 - <<'PY'
from pathlib import Path
import re

html = Path("secure-mail.html").read_text(
    encoding="utf-8",
    errors="ignore"
)

js = re.search(
    r"<script[^>]*>(.*?)</script>",
    html,
    re.S
).group(1)

Path("challenge.js").write_text(
    js,
    encoding="utf-8"
)
PY
```

추출한 JavaScript를 정리한다.

```bash
pip install jsbeautifier
js-beautify challenge.js -o challenge.pretty.js
```

이후 VS Code에서 다음 문자열을 검색하면 핵심 함수로 이동할 수 있다.

```text
function _0x9a220
```

---

### 원본 핵심 코드

원본 코드는 거의 한 줄로 붙어 있으며, 핵심 부분만 정리하면 다음과 같다.

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
        _0x2fef58['decrypt'](file);

    // 복호화된 바이트를 문자열로 변환
    // MD5 검증
    // document.write로 이미지 출력
}
```

이 코드를 바로 읽기는 어렵기 때문에 난독화 구조부터 확인해야 한다.

---

### 난독화 구조

코드 상단에는 매우 많은 문자열이 들어 있는 배열이 존재한다.

```javascript
var _0x2297 = [
    'W7OkEmokW5OKfGar',
    'pfHcWP/cS8oTWPFcJNi=',
    'EsxdHSkRFgevzcO=',
    ...
];
```

이 배열은 실제 문자열을 직접 저장하지 않고 Base64와 RC4 방식으로 변형된 문자열들을 저장하고 있다.

그 아래에는 배열을 회전시키는 코드가 존재한다.

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

이 코드는 `_0x2297` 배열의 순서를 변경한다. 따라서 단순히 배열 인덱스만 보고는 원래 문자열을 확인하기 어렵다.

이후 `_0x2439` 함수가 문자열 디코더 역할을 한다.

```javascript
var _0x2439 = function (
    _0x35fa1a,
    _0x2297e4
) {
    _0x35fa1a =
        _0x35fa1a - 0x0;

    var _0x2439b6 =
        _0x2297[_0x35fa1a];

    ...

    _0x2439b6 =
        _0x2439['sUjgBF'](
            _0x2439b6,
            _0x2297e4
        );

    return _0x2439b6;
};
```

호출 형태는 다음과 같다.

```javascript
_0x2439('0x99', '3itY')
```

첫 번째 인자는 문자열 배열의 위치이며, 두 번째 인자는 RC4 복호화에 사용되는 키이다.

그리고 다음과 같이 별칭이 만들어진다.

```javascript
var _0x225843 = _0x2439;
```

따라서 다음 두 표현은 같은 의미이다.

```javascript
_0x2439('0x99', '3itY')
_0x225843('0x99', '3itY')
```

`_0x9a220` 함수 안에서는 다시 별칭이 만들어진다.

```javascript
var _0x540d50 = _0x225843;
```

따라서 다음 코드는 런타임에 문자열을 복호화한 뒤 실제 속성명으로 사용한다.

```javascript
Array[
    _0x540d50('0x99', '3itY')
]
```

복호화 결과는 다음 의미가 된다.

```javascript
Array.from
```

마찬가지로 다음 코드는:

```javascript
[
    _0x540d50('0xe2', 'G(su')
]
```

다음 의미가 된다.

```javascript
.map
```

따라서 원본 코드:

```javascript
Array[
    _0x540d50('0x99', '3itY')
](
    _0x3eebe5(
        _0x30bf04,
        null,
        true
    )
)[
    _0x540d50('0xe2', 'G(su')
](
    x => x.charCodeAt()
)
```

는 다음과 같이 해석할 수 있다.

```javascript
Array.from(
    _0x3eebe5(
        password,
        null,
        true
    )
).map(
    x => x.charCodeAt()
)
```

---

### 난독화 문자열 실제 값 확인

브라우저에서 HTML 파일을 연 다음 F12를 눌러 Console 탭으로 이동한다.

다음과 같이 디코더를 직접 호출하면 실제 문자열을 확인할 수 있다.

```javascript
_0x225843('0x99', '3itY')
_0x225843('0xe2', 'G(su')
```

여러 개를 한 번에 확인할 수도 있다.

```javascript
[
    _0x225843('0x99', '3itY'),
    _0x225843('0xe2', 'G(su'),
    _0x225843('0x29', 'd%09')
]
```

이 방법은 난독화 문자열을 직접 하나씩 확인하는 방식이다.

하지만 전체 문자열을 모두 해제할 필요는 없다. 이 문제에서는 다음과 같은 이미 드러난 문자열들이 존재한다.

```text
charCodeAt
decrypt
Cipher Block Chaining
document.write
file
```

이 문자열들을 기준으로 데이터 흐름을 추적하면 핵심 로직을 복원할 수 있다.

---

### `_0x3eebe5`가 MD5인 이유

`_0x9a220` 함수에서 입력값은 다음 함수로 전달된다.

```javascript
_0x3eebe5(
    _0x30bf04,
    null,
    true
)
```

`_0x3eebe5` 함수는 다음과 같은 구조이다.

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

인자의 의미를 정리하면 다음과 같다.

```text
첫 번째 인자: 해시할 메시지
두 번째 인자: HMAC 키
세 번째 인자: raw 출력 여부
```

현재 호출은 다음과 같다.

```javascript
_0x3eebe5(
    password,
    null,
    true
)
```

두 번째 인자가 `null`이므로 일반 해시를 수행하며, 세 번째 인자가 `true`이므로 16진수 문자열이 아니라 raw 바이트를 반환한다.

즉 다음과 같다.

```text
raw MD5(password)
```

또한 내부 함수 `_0x1bb977`에는 다음 상수들이 존재한다.

```javascript
0x67452301
-0x10325477
-0x67452302
0x10325476
```

이 값들을 32비트 unsigned 값으로 표현하면 다음과 같다.

```text
0x67452301
0xefcdab89
0x98badcfe
0x10325476
```

이는 MD5 알고리즘의 초기 레지스터 값과 정확히 일치한다.

또한 내부에는 MD5의 4개 라운드 연산에 해당하는 함수들이 존재한다.

```text
_0x3170e2
_0x55dc4e
_0x182ec0
_0x5527b8
```

각 함수는 MD5의 F, G, H, I 연산에 해당한다.

따라서 `_0x3eebe5`는 MD5 및 HMAC-MD5를 구현한 함수이며, 현재 호출 방식에서는 raw MD5 결과 16바이트를 반환한다.

---

### MD5 결과를 바이트 배열로 변환

`_0x3eebe5`의 반환값은 raw 문자열이다.

```javascript
_0x3eebe5(
    password,
    null,
    true
)
```

이 문자열의 각 문자를 `charCodeAt()`으로 변환한다.

```javascript
Array.from(
    rawMD5
).map(
    x => x.charCodeAt()
)
```

결과는 다음과 같은 16바이트 배열이다.

```text
[
    MD5 byte 0,
    MD5 byte 1,
    ...
    MD5 byte 15
]
```

이 배열이 `_0x2ee89c` 변수에 저장된다.

---

### AES-CBC 확인

코드 안에는 다음 문자열이 직접 존재한다.

```javascript
'Cipher Block Chaining'
```

해당 문자열은 `_0x2ef5df` 생성자 안에 있다.

```javascript
var _0x2ef5df = function (
    _0x4d87e7,
    _0x1687b7
) {
    this[...] =
        'Cipher Block Chaining';

    ...

    this['_0x274b61'] =
        _0x2cacb0(
            _0x1687b7,
            true
        );

    this[...] =
        new _0x46dc18(
            _0x4d87e7
        );
};
```

첫 번째 인자는 AES key이며, 두 번째 인자는 IV이다.

`_0x9a220`에서는 다음과 같이 같은 값을 두 번 전달한다.

```javascript
new CBC(
    _0x2ee89c,
    _0x2ee89c
)
```

따라서 실제 암호화 설정은 다음과 같다.

```text
AES key = MD5(password)
AES IV  = MD5(password)
Mode    = CBC
```

즉 입력된 생일의 MD5 값이 AES key와 IV로 동시에 사용된다.

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
    _0x2fef58['decrypt'](
        file
    );
```

따라서 `file` 배열은 AES-CBC 암호문이다.

복호화된 바이트는 `String.fromCharCode()`를 통해 문자열로 변환된다.

```javascript
plaintext = "";

for (
    let i = 0;
    i < dfbora.length;
    i++
) {
    plaintext +=
        String.fromCharCode(
            dfbora[i]
        );
}
```

정상적으로 복호화되면 평문은 다음 형식으로 시작한다.

```text
data:image/png;base64,
```

마지막으로 이 문자열을 이미지의 `src` 속성에 넣는다.

```javascript
document.write(
    '<img src="' +
    plaintext +
    '">'
);
```

---

### 취약점

이 문제의 핵심 취약점은 암호화 자체보다 매우 작은 비밀번호 공간과 클라이언트 측 검증 구조에 있다.

입력값은 6자리 생일이다.

```text
YYMMDD
```

가능한 모든 숫자를 검사하더라도 최대 경우의 수는 다음과 같다.

```text
000000 ~ 999999
```

즉 최대 1,000,000개이다. 실제 날짜만 생성하면 약 36,500개 정도만 검사하면 된다.

또한 다음 요소들이 모두 클라이언트에 노출되어 있다.

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

MD5에는 salt가 없으며, AES key와 IV가 동일한 값이다. 따라서 서버와 통신하지 않고도 완전한 오프라인 브루트포싱이 가능하다.

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

