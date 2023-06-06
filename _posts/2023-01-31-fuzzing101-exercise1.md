---
layout: post
title: "[Fuzzing101] Exercise 1 - Xpdf"
date: 2023-01-31 11:35:00 +0900
categories: [Security, Fuzzing]
tags: [afl, fuzzing]
---

![result](2023-01-31-fuzzing/1_result.png)

Fuzzing101은 Fuzz testing(or Fuzzing)에 관한 실습을 할 수 있도록, 총 10개의 Exercise를 꾸려놓은 레포지토리입니다.

AFL++을 다루며, Xpdf부터 V8까지 다양한 소프트웨어에서 퍼징을 돌리고, 취약점을 찾아보는 실습을 수행할 수 있습니다.

모든 Exercise를 수행할 수 있을지는 모르겠지만, 오늘은 그 첫 번째 단계인 Exercise 1 - Xpdf를 준비했습니다.

[https://github.com/antonio-morales/Fuzzing101](https://github.com/antonio-morales/Fuzzing101)

---

## 1. Build Fuzzer

Fuzzing101에서 제공해준 VMware 이미지 파일이 있습니다. Ubuntu 20.04 iso를 깔기 귀찮다면, 아래 링크를 통해서 설치하면 될 것 같습니다. 물론, VirtualBox는 직접 설치해야 합니다. (아이디랑 비밀번호 모두 fuzz입니다.)

[https://drive.google.com/file/d/1_m1x-SHcm7Muov2mlmbbt8nkrMYp0Q3K/view?usp=sharing](https://drive.google.com/file/d/1_m1x-SHcm7Muov2mlmbbt8nkrMYp0Q3K/view?usp=sharing)

```
sudo apt update && sudo apt-get update
sudo apt-get install -y python3-pip cmake build-essential git gcc
git clone https://github.com/AFLplusplus/AFLplusplus && cd AFLplusplus
export LLVM_CONFIG="llvm-config-11"
make
make install
```

만약 unicornafl 관련 에러가 뜬다면, 그냥 무시하고 진행해도 큰 문제 없을 것 같습니다. 저는 그대로 진행했는데 큰 문제가 없었습니다.

## 2. Run Fuzzer

```
afl-fuzz -i $HOME/fuzzing_xpdf/pdf_examples/ -o $HOME/fuzzing_xpdf/out/ -s 123 -- $HOME/fuzzing_xpdf/install/bin/pdftotext @@ $HOME/fuzzing_xpdf/output
```

- `-i` : AFL Fuzzer의 입력 케이스가 저장된 디렉토리
- `-o` : AFL Fuzzer가 mutate한 파일을 저장할 디렉토리
- `-s` : AFL Fuzzer에 지정할 랜덤 시드
- `@@` : AFL의 입력으로 사용할 placeholder

`--` 뒤에부터 실제 입력되는 커맨드라인입니다.

## 3. Triage Crashes

- backtrace 모음
    
    [0x00] `Lexer::getObj(Object*)+7737` - stack overflow
    
    ```
    Error: PDF file is damaged - attempting to reconstruct xref table...
    Error (3608): Missing 'endstream'
    
    *RSP  0x7fffff7fefe0
    
     ► 0x7ffff7b0deb1 <_int_malloc+1089>    mov    qword ptr [rsp + 8], rax
    
     ► f 0   0x7ffff7b0deb1 _int_malloc+1089
       f 1   0x7ffff7b10154 malloc+116
       f 2         0x4dde21 copyString+49
       f 3         0x4dde21 copyString+49
       **f 4         0x493c29 Lexer::getObj(Object*)+7737**
       f 5         0x49dada
       f 6         0x49dada
       f 7         0x49df47
    ```
    
    [0x01] `Lexer::getObj(Object*)+7737` - stack overflow
    
    ```
    Error: PDF file is damaged - attempting to reconstruct xref table...
    Error (407): Dictionary key must be a name object
    Error (407): Dictionary key must be a name object
    Error (441): Dictionary key must be a name object
    Error (475): Dictionary key must be a name object
    Error (476): Dictionary key must be a name object
    Error (481): Dictionary key must be a name object
    Error (1608): Dictionary key must be a name object
    Error (1613): Dictionary key must be a name object
    Error (1826): Dictionary key must be a name object
    
    RSP  0x7fffff7fefe0
    
    ► 0x7ffff7b0deb1 <_int_malloc+1089>    mov    qword ptr [rsp + 8], rax
    
     ► f 0   0x7ffff7b0deb1 _int_malloc+1089
       f 1   0x7ffff7b10154 malloc+116
       f 2         0x4dde21 copyString+49
       f 3         0x4dde21 copyString+49
       **f 4         0x493c29 Lexer::getObj(Object*)+7737**
       f 5         0x49dada
       f 6         0x49dada
       f 7         0x49df47
    ```
    
    [0x02] `Lexer::getObj(Object*)+7737` - stack overflow
    
    ```
    Error: PDF file is damaged - attempting to reconstruct xref table...
    Error (375): Dictionary key must be a name object
    Error (375): Dictionary key must be a name object
    Error (409): Dictionary key must be a name object
    Error (443): Dictionary key must be a name object
    Error (444): Dictionary key must be a name object
    Error (449): Dictionary key must be a name object
    Error (1794): Dictionary key must be a name object
    Error (2368): Dictionary key must be a name object
    Error (2382): Dictionary key must be a name object
    Error (2384): Dictionary key must be a name object
    Error (2387): Dictionary key must be a name object
    Error (2390): Dictionary key must be a name object
    Error: Unknown font type: '???'
    
    *RSP  0x7fffff7feff0
    
    ► 0x7ffff7b0deb1 <_int_malloc+1089>    mov    qword ptr [rsp + 8], rax
    
     ► f 0   0x7ffff7b0deb1 _int_malloc+1089
       f 1   0x7ffff7b10154 malloc+116
       f 2         0x4dde21 copyString+49
       f 3         0x4dde21 copyString+49
       **f 4         0x493c29 Lexer::getObj(Object*)+7737**
       f 5         0x49dada
       f 6         0x49dada
       f 7         0x49df47
    ```
    
    [0x03] `Lexer::getObj(Object*)+1634` - stack overflow
    
    ```
    ...
    Error (1998): Illegal character '>'
    Error (2002): Dictionary key must be a name object
    Error (2004): Dictionary key must be a name object
    Error (2282): Missing 'endstream'
    
    *RBP  0x7fffff7ff4a0 —▸ 0x7fffff801b80 ◂— 0x7ce
    *RSP  0x7fffff7fef30
    
     ► 0x7ffff7aec881 <__vfprintf_internal+33>     mov    dword ptr [rbp - 0x4c0], ecx
    
     ► f 0   0x7ffff7aec881 __vfprintf_internal+33
       f 1   0x7ffff7aefea2 buffered_vfprintf+194
       f 2   0x7ffff7aecd24 __vfprintf_internal+1220
       f 3   0x7ffff7ad7c6a fprintf+154
       f 4         0x418327
       **f 5         0x492452 Lexer::getObj(Object*)+1634**
       f 6         0x49dada
       f 7         0x49dada
    
    pwndbg> x/i 0x418327
       0x418327 <error(int, char*, ...)+263>:	jmp    0x418355 <error(int, char*, ...)+309>
    ```
    

`Lexer::getObj(Object*)+7737` 부분에서 stack overflow가 터지는 것을 확인했습니다.

그러나, Backtrace를 더 내려가 보면, 추가적인 함수를 확인할 수 있습니다.

```
 ► f 0   0x7ffff7b0deb1 _int_malloc+1089
   f 1   0x7ffff7b10154 malloc+116
   f 2         0x4dde21 copyString+49
   f 3         0x4dde21 copyString+49
   f 4         0x493c29 Lexer::getObj(Object*)+7737
   f 5         0x49dada
   f 6         0x49dada
   f 7         0x49df47

pwndbg> x/i 0x49dada
  0x49dada <Parser::getObj(Object*, unsigned char*, CryptAlgorithm, int, int, int)+3098>
pwndbg> x/i 0x49dada
  0x49dada <Parser::getObj(Object*, unsigned char*, CryptAlgorithm, int, int, int)+3098>
pwndbg> x/i 0x49df47
  0x49df47 <Parser::getObj(Object*, unsigned char*, CryptAlgorithm, int, int, int)+4231>
```

이는 우리가 찾고자 하는 CVE-2019-13288가 Parser::getObj 함수에서 터지는 취약점이라는 점과 일치합니다. 따라서, CVE를 트리거할 수 있는 입력을 획득한 것입니다.

## 4. Analysis Root Cause

`0x49e0c4 <Parser::getObj + 4612>:	call 0x49e530 <Parser::makeStream>`

위 주소에 breakpoint를 걸고, continue를 계속 해 보았을 때, 아래와 같은 backtrace를 반복해서 관측할 수 있습니다.

```
 **► f 0         0x49e0c4**
   **f 1         0x4d0641
   f 2         0x49e5e5 
   f 3         0x49e5e5
   f 4         0x49e0c9**
   **f 5         0x4d0641
   f 6         0x49e5e5
   f 7         0x49e5e5**
```

`0x49e0c4`가 실행되고 나면, backtrace에는 `0x49e0c9`가 남게될 것이므로(call하고 나면, 현재 주소 + 5가 스택에 남게 되므로), 결국 빨간색과 초록색은 같은 실행 루틴임을 알 수 있습니다.

```
 **► f 0         0x49e0c4**
   **f 1         0x4d0641
   f 2         0x49e5e5
   f 3         0x49e5e5**
   **f 4         0x49e0c9
   f 5         0x4d0641**
   **f 6         0x49c426**
   f 7         0x49c0ec
```

`0x49e0c4`에 breakpoint를 걸었을 때, 맨 처음에 확인할 수 있는 backtrace입니다.

```
**0x49e0c4 <Parser::getObj+4612>: call   0x49e530 <Parser::makeStream>
0x49e5e0 <Parser::makeStream+176>: call   0x417f90 <Dict::lookup>**
**0x4d063c <XRef::fetch+1068>: call   0x49cec0 <Parser::getObj>
0x49c421 <Page::displaySlice+801>: call   0x4988a0 <Object::fetch>**
```

```
1. **XRef::fetch**
2. **Parser::getObj**
3. **Parser::makeStream**
4. **Dict::lookup**
5. 다시 1번 반복
```

```c
class Object {
public:
  ...

  // If object is a Ref, fetch and return the referenced object.
  // Otherwise, return a copy of the object.
  Object *fetch(XRef *xref, Object *obj);

  ...

private:
  ObjType type;			// object type
  union {			// value for each type:
    GBool booln;		//   boolean
    int intg;			//   integer
    double real;		//   real
    GString *string;		//   string
    char *name;			//   name
    Array *array;		//   array
    Dict *dict;			//   dictionary
    Stream *stream;		//   stream
    Ref ref;			//   indirect reference
    char *cmd;			//   command
  };
};
```

```c
Object * Parser::getObj(Object * obj, Guchar * fileKey,
  CryptAlgorithm encAlgorithm, int keyLength,
  int objNum, int objGen) {
  char * key;
  Stream * str;
  Object obj2;
  int num;
  DecryptStream * decrypt;
  GString * s, * s2;
  int c;

  // refill buffer after inline image data
  if (inlineImg == 2) {
    ...
  }

  // array
  if (buf1.isCmd("[")) {
    ...
  } // dictionary or stream (buf1->cmd가 "<<"일 때)
	else if (buf1.isCmd("<<")) {
    shift();
    obj -> initDict(xref);
    
    // buf1->cmd != ">>"이고, buf1->type != objEOF일 때,
    while (!buf1.isCmd(">>") && !buf1.isEOF()) {
      if (!buf1.isName()) {
        error(getPos(), "Dictionary key must be a name object");
        shift();
      } else { // 이 부분 실행 (name은 cmd와 같음. union 형태라서 같은 주소를 담고 있음.)
        key = copyString(buf1.getName());
        shift();
        if (buf1.isEOF() || buf1.isError()) {
          gfree(key);
          break;
        }
        obj -> dictAdd(key, getObj(&obj2, fileKey, encAlgorithm, keyLength,
          objNum, objGen));
      }
    }
    if (buf1.isEOF())
      ...
    
		// stream objects are not allowed inside content streams or
    // object streams
    if (allowStreams && buf2.isCmd("stream")) {
      // 이 부분 실행
      if ((str = makeStream(obj, fileKey, encAlgorithm, keyLength, objNum, objGen)))
				...
```

```c
Stream *Parser::makeStream(Object *dict, Guchar *fileKey,
			   CryptAlgorithm encAlgorithm, int keyLength,
			   int objNum, int objGen) {
  Object obj;
  BaseStream *baseStr;
  Stream *str;
  Guint pos, endPos, length;

  // get stream start position
  lexer->skipToNextLine();
  pos = lexer->getPos();

  // get length (object->dict->lookup("Length", &obj))
  dict->dictLookup("Length", &obj);
	...
}
```

```c
struct DictEntry {
  char *key;
  Object val;
};

class Dict {
public:
	...
private:
  XRef *xref;			// the xref table for this PDF file
  DictEntry *entries;		// array of entries
  int size;			// size of <entries> array
  int length;			// number of entries in dictionary
  int ref;			// reference count

  DictEntry *find(char *key);
};

inline DictEntry *Dict::find(char *key) {
  for (int i = 0; i < length; ++i) {
    if (!strcmp(key, entries[i].key))
      return &entries[i];
  }
  return NULL;
}

Object *Dict::lookup(char *key, Object *obj) {
  DictEntry *e;
  return (e = find(key)) ? e->val.fetch(xref, obj) : obj->initNull();
}
```

```
**pwndbg>** x/3gx dict->dict->entries
0x7a12c0:	0x00000000007a14c0	0x0000000000000009
0x7a12d0:	0x0000000000000007
**pwndbg>** x/s 0x00000000007a14c0
0x7a14c0:	**"Length"**
```

makeStream 함수가 호출되었을 때, entries의 첫 번째 인자가 “Length”를 포함하고 있습니다. 따라서, 그 뒤에 있는 9와 7이 Object의 값이 됩니다.

```
**pwndbg>** x/gx objRef 
0x9:	Cannot access memory at address 0x9
```

이때, type에 해당하는 값이 9인데, 이는 objRef(9)와 값이 같습니다.

```c
Object *Object::fetch(XRef *xref, Object *obj) {
  return (type == objRef && xref) ?
         xref->fetch(ref.num, ref.gen, obj) : copy(obj);
}
```

따라서, type이 objRef에 해당하기 때문에, 인자로 전달된 객체인 xref를 참조하여, fetch 메소드가 실행됩니다. 이때, 인자로 전달되는 값은 makeStream 함수의 인자로 전해졌던 `dict->dict->xref`입니다. 또한, ref는 `dict->dict->entries[0].val.ref`입니다.

```
struct Ref {
  int num;			// object number
  int gen;			// generation number
};

**pwndbg>** p dict->dict->entries[0].val.ref
$12 = {
  num = 7,
  gen = 0
}

**pwndbg>** p/x dict->dict->xref
$8 = 0x7a2230
```

```c
enum XRefEntryType {
  xrefEntryFree,
  xrefEntryUncompressed,
  xrefEntryCompressed
};

struct XRefEntry {
  Guint offset;
  int gen;
  XRefEntryType type;
};

class XRef {
public:
  ...
  // Fetch an indirect reference.
  Object *fetch(int num, int gen, Object *obj);
  ...
private:
  ...
  XRefEntry *entries;		// xref entries
  int size;			// size of <entries> array
  int rootNum, rootGen;		// catalog dict
  GBool ok;			// true if xref table is valid
  int errCode;			// error code (if <ok> is false)
  Object trailerDict;		// trailer dictionary
  Guint lastXRefPos;		// offset of last xref table
  Guint *streamEnds;		// 'endstream' positions - only used in
				//   damaged files
  int streamEndsLen;		// number of valid entries in streamEnds
  ObjectStream *objStr;		// cached object stream
  GBool encrypted;		// true if file is encrypted
  int permFlags;		// permission bits
  GBool ownerPasswordOk;	// true if owner password is correct
  Guchar fileKey[16];		// file decryption key
  int keyLength;		// length of key, in bytes
  int encVersion;		// encryption version
  CryptAlgorithm encAlgorithm;	// encryption algorithm

  ...
};

Object * XRef::fetch(int num, int gen, Object * obj) {
  XRefEntry * e;
  Parser * parser;
  Object obj1, obj2, obj3;

  // check for bogus ref - this can happen in corrupted PDF files
  if (num < 0 || num >= size) {
    goto err;
  }

  e = &entries[num];
  switch (e -> type) {
  case xrefEntryUncompressed: // 1
    if (e -> gen != gen) {
      goto err;
    }
    obj1.initNull();
    parser = new Parser(this,
      new Lexer(this,
        str->makeSubStream(start + e -> offset, gFalse, 0, & obj1)),
      gTrue);
    parser->getObj(&obj1);
    parser->getObj(&obj2);
    parser->getObj(&obj3);
    if (!obj1.isInt() || obj1.getInt() != num ||
      !obj2.isInt() || obj2.getInt() != gen ||
      !obj3.isCmd("obj")) {
      obj1.free();
      obj2.free();
      obj3.free();
      delete parser;
      goto err;
    }
    parser->getObj(obj, encrypted ? fileKey : (Guchar * ) NULL,
      encAlgorithm, keyLength, num, gen);
    ...
}
```

```
**pwndbg>** p/x dict->dict->xref->entries[7]
$18 = {
  offset = 0x6b7,
  gen = 0x0,
  type = 0x1
}
```

Parser::getObj→Parser::makeStream→Dict::lookup→XRef::fetch→Parser::getObj이 루틴이 무한정으로 반복되는 것으로 보입니다.

이걸 패치하려면, Parser::getObj 함수의 인자에서 특정 값이 오면 goto err로 패치해버리거나, 제대로 패치하려면 각 값이 어떻게 세팅되었는지 알아야 할 것입니다.

---

똑같은 내용을 분석한 동아리 부원은 buf2가 “stream”으로 세팅되는 부분을 찾아서 취약점을 트리거하는 부분을 찾고자 했습니다.

저도 다음 내용부터는 그런 식으로 원인을 확실히 파악하고, PoC에 해당하는 값을 찾아 보겠습니다.. 😎