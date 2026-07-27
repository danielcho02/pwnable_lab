# 🧠 Double Free Bug
`tcahce`와 `bins`를 free list라 통칭한다면, free list 관점에서
`free`는 chunk를 추가하는 함수, `malloc`은 청크를 꺼내는 함수
임의 청크에 대해 `free`를 두 번 이상 적용 = 같은 청크를 free list에 여러 번 추가 가능
duplicated free list를 이용하면 임의 주소에 청크를 할당할 수 있음

## 📌 Definition
DFB = 같은 청크를 두 번 해체할 수 있는 버그

---

## 📄


---

## 📄 
---

## 📄 


---

## ✅ Key Takeaways
