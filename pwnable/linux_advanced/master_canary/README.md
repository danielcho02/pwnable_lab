# 🧠 Master Canary

## 📌 Definition
`Stack Smaching Protector(SSP)` = `Stack Canary`: Stack Buffer Overflow로 부터 반환 주소를 보호하는 기법
`Thread Local Storage(TLS)`: Stack Canary의 값이 존재하는 위치 

---

## 📄 `Thread Local Storage(TLS)`
= Thread의 전역 변수를 저장하기 위한 공간, Loader에 의해서 할당
```c
static void *
init_tls (void)
{
  /* Construct the static TLS block and the dtv for the initial
     thread.  For some platforms this will include allocating memory
     for the thread descriptor.  The memory for the TLS block will
     never be freed.  It should be allocated accordingly.  The dtv
     array can be changed if dynamic loading requires it.  */
  void *tcbp = _dl_allocate_tls_storage ();
  if (tcbp == NULL)
    _dl_fatal_printf ("\
cannot allocate TLS data structures for initial thread\n");

  /* Store for detection of the special case by __tls_get_addr
     so it knows not to pass this dtv to the normal realloc.  */
  GL(dl_initial_dtv) = GET_DTV (tcbp);

  /* And finally install it for the main thread.  */
  const char *lossage = TLS_INIT_TP (tcbp);
  if (__glibc_unlikely (lossage != NULL))
    _dl_fatal_printf ("cannot set up thread-local storage: %s\n", lossage);
  tls_init_tp_called = true;

  return tcbp;
}
```
`init_tls` = TLS 영역 할당, 초기화
`FS` = x86 계열 CPU의 세그먼트 레지스터(CS, DS, SS, ES, FS, GS) 중 하나
`ARCH_SET_FS` = TLS영역의 시작 주소를 FS base로 설정

---

## 📄 Master Canary
### 1. Master Canary
```text
FS:0x28에 원본 카나리 존재
        ↓
각 함수가 자신의 스택에 복사
        ↓
다른 함수에서 Canary leak
        ↓
오버플로우 payload에 같은 카나리 삽입
        ↓
SSP 검사 통과
        ↓
Return Address 조작
```
`Master Canary` = TLS base(=FS base) + 0x28

### 2. Canary 값 생성
```c
static void
security_init (void)
{
  /* Set up the stack checker's canary.  */
  uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random);
#ifdef THREAD_SET_STACK_GUARD
  THREAD_SET_STACK_GUARD (stack_chk_guard);
#else
  __stack_chk_guard = stack_chk_guard;
#endif

  /* Set up the pointer guard as well, if necessary.  */
  uintptr_t pointer_chk_guard
    = _dl_setup_pointer_guard (_dl_random, stack_chk_guard);
#ifdef THREAD_SET_POINTER_GUARD
  THREAD_SET_POINTER_GUARD (pointer_chk_guard);
#endif
  __pointer_chk_guard_local = pointer_chk_guard;

  /* We do not need the _dl_random value anymore.  The less
     information we leave behind, the better, so clear the
     variable.  */
  _dl_random = NULL;
}
```
`security_init` = TLS영역에 랜덤한 카나리 값을 삽입
`_dl_random`을 인자로 카나리 생성

```c
static inline uintptr_t __attribute__ ((always_inline))
_dl_setup_stack_chk_guard (void *dl_random)
{
  union
  {
    uintptr_t num;
    unsigned char bytes[sizeof (uintptr_t)];
  } ret = { 0 };

  if (dl_random == NULL)
    {
      ret.bytes[sizeof (ret) - 1] = 255;
      ret.bytes[sizeof (ret) - 2] = '\n';
    }
  else
    {
      memcpy (ret.bytes, dl_random, sizeof (ret));
#if BYTE_ORDER == LITTLE_ENDIAN
      ret.num &= ~(uintptr_t) 0xff;
#elif BYTE_ORDER == BIG_ENDIAN
      ret.num &= ~((uintptr_t) 0xff << (8 * (sizeof (ret) - 1)));
```
```text
커널이 AT_RANDOM에 랜덤 16바이트 제공
        ↓
_dl_random이 그 랜덤 바이트의 주소를 가리킴
        ↓
_dl_setup_stack_chk_guard(_dl_random)
        ↓
그중 8바이트를 복사하고 첫 바이트를 0x00으로 변경
        ↓
완성된 카나리를 TLS의 stack_guard에 저장
        ↓
x86-64에서는 FS:0x28로 접근
```
```text
_dl_random
= 커널이 준 랜덤 바이트를 가리키는 포인터

_dl_setup_stack_chk_guard()
= 랜덤값 일부를 복사해 카나리를 만드는 함수

최종 64비트 카나리
= NULL 1바이트 + 랜덤 7바이트

첫 바이트가 NULL인 이유
= 문자열 기반 leak과 overwrite를 더 어렵게 만들기 위해서

반환된 카나리
→ 이후 TLS의 stack_guard에 저장
→ x86-64에서는 FS:0x28로 접근
```

### 3. Canary 값 삽입
```c
/* Set the stack guard field in TCB head.  */
#define THREAD_SET_STACK_GUARD(value) \
  THREAD_SETMEM (THREAD_SELF, header.stack_guard, value)
```
`THREAD_SET_STACK_GUARD` = TLS + 0x28 위치에 생성된 값을 삽입하는 매크로

---

