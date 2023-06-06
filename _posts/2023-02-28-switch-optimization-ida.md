---
layout: post
title: "IDA switch문이 jmp rax로 최적화되었을 때 해결법"
date: 2023-02-28 09:00:00 +0900
categories: [Security, System Hacking]
tags: [pwnable, trouble shooting]
---

![cover](2023-02-28-ida/dominik-vanyi-5Fxuo7x-eyg-unsplash.jpg){: width="50%" height="50%"}

포너블을 풀다 보면, 아래 예제(`switch.c`)와 같이, switch의 case 수가 5개가 넘어갈 경우 점프 테이블을 사용하도록 최적화되어 IDA 디컴파일러가 제대로 동작하지 않는 것을 심심찮게 볼 수 있습니다. (switch 최적화가 jump table 방식만 있는 것은 아닙니다.)

개별적인 jmp마다 실행되는 어셈블리 내용을 직접 확인하고, 해당 내용을 따로 정리하면서 풀곤 했었는데요.

IDA에서 이를 직접 패치할 수 있도록 기능을 제공하고 있다는 걸 최근에야 알게 되었고, 이를 공유하고자 합니다!

---

```c
// switch.c
// gcc -o switch switch.c
#include <stdio.h>

int main() {
    int input;
    while (1) {
        scanf("%d", &input);
        switch(input) {
            case 1:
                printf("your input is 1");
                break;
            case 2:
                printf("your input is 2");
                break;
            case 3:
                printf("your input is 3");
                break;
            case 4:
                printf("your input is 4");
                break;
            case 5:
                printf("your input is 5");
                break;
        }
    }
}
```

위의 코드를 컴파일한 뒤, IDA로 해당 프로그램을 디컴파일 할 경우, 다음과 같은 내용을 확인할 수 있습니다.

![ida](2023-02-28-ida/ida.png)

어김없이 `jmp rax`로 내용이 생략되었습니다.

또한, C언어에서는 어떤 함수가 호출되며 인자가 무엇인지 확인할 수 있으나, IDA에서는 이를 보여주지 않습니다.

이제 해결법을 따라해 봅시다.

## Specify switch idiom...

IDA의 디스어셈블러 창에서 `Edit -> Other -> Specify switch idiom...`을 클릭하면 아래와 같은 화면을 볼 수 있습니다.

![ida2](2023-02-28-ida/ida2.png)

- Address of jump table
- Number of elements
- Size of table element
- Element shift amount
- Element base value
- Start of switch idiom
- input register of switch
- First(lowest) input value
- Default jump address

위의 값만 입력해주면, switch문이 복구된 IDA 디컴파일 결과를 확인할 수 있습니다.

### 1. Address of jump table

switch jump table 최적화는 일반적으로 입력된 값에 대한 상한을 확인하고, 이후에 jump table을 사용하여 분기합니다.

```
target = base +/- (table_element << shift)
```

switch의 분기 주소를 확인하기 위한 일반적인 방정식은 위와 같습니다. 이때, `base`와 `shift`는 사용되지 않을 경우 0으로 세팅하면 됩니다.

IDA에서 일반적으로 볼 수 있는 방식은 아래라고 생각하면 됩니다.

```
target = jump_table +/- jump_table[rax * size]
```

디스어셈블러 윈도우로 이동해서 어떤 값을 넣어야 하는지 확인해 봅시다.

![ida3](2023-02-28-ida/ida3.png)

먼저, scanf로 입력을 받았습니다.

이후에, 6 이상의 값이 입력되었을 경우, `loc_1184`로 이동합니다.

마지막으로, 입력 값에 4를 곱한 뒤, `unk_2058 + unk_2058[rax * 4]`을 수행합니다.

그러면, jump table의 주소는 `unk_2058`일 것입니다.

(PIE가 걸려 있는 경우 상대 주소를 사용하기에 값이 작은 게 맞습니다. 절대 주소를 사용할 경우 절대 주소 그대로 넣어 주면 됩니다.)

### 2. Number of elements

jump table에서 가진 element의 개수를 씁니다.

5 이하의 값에 대해 별도로 분기를 수행하므로, 6개의 element가 있는 상태입니다.

### 3. Size of table element

`0x11B5` 주소를 보면, `eax` 레지스터로 jump table의 값을 받고 있습니다.

따라서, jump table의 값은 4바이트 크기를 지니고 있음을 알 수 있으며, Size of table element에는 4를 넣어주면 됩니다.

### 4. Element shift amount

shift를 사용한 최적화가 존재할 경우 값을 넣어주면 되는데, 위 코드를 봤을 때 그런 내용은 없으므로 0으로 채워줍니다. (이 내용은 ARM에서 switch문을 최적화할 경우 간혹 등장하는 것 같습니다.)

### 5. Element base value

분기를 수행할 때의 base 주소를 넣어주면 됩니다. 위에서는 jump table이 그대로 base로 활용되고 있으므로, `unk_2058`를 넣어주면 됩니다.

### 6. Start of switch idiom

switch 문의 시작 주소를 적어주면 됩니다.

변수를 로드하고 상한치를 확인하는 코드와 jump table을 사용하는 코드 중 하나를 골라주면 되는데, 저는 전자를 사용하겠습니다.

### 7. input register of switch

입력으로 사용되는 레지스터를 적어주면 됩니다. scanf 함수의 수행 결과를 `eax` 레지스터에 담아 상한치를 비교하고 있으므로, `eax` 레지스터를 접어줍시다.

### 8. First(lowest) input value

jump table의 가장 낮은 입력 값을 적어주면 됩니다. 0부터 5까지 jump table의 인덱스로 활용하고 있으므로, 0을 적어줍니다.

### 9. Default jump address

상한치를 확인했을 때, jmp가 수행되는 주소를 적어주면 됩니다.

이렇게 모든 값을 입력하고 나면, 비로소 제대로 디컴파일된 IDA hex-ray 내용을 확인할 수 있게 됩니다.

![ida5](2023-02-28-ida/ida5.png)


### 10. 총정리

아래는 위의 내용을 모두 정리한 스크린샷입니다. 각 색깔에 맞게 내용을 확인할 수 있으므로, 위의 내용이 이해되지 않으셨다면 아래 사진도 참고하시면 좋을 것 같습니다!

![ida4](2023-02-28-ida/ida4.png)

## Reference

- IDA hexray 공식 블로그 : [https://hex-rays.com/blog/igors-tip-of-the-week-53-manual-switch-idioms](https://hex-rays.com/blog/igors-tip-of-the-week-53-manual-switch-idioms)
- mhibio님의 블로그 : [https://mhibio.tistory.com/105](https://mhibio.tistory.com/105)
- ChinaNuke님의 블로그 : [https://www.nuke666.cn/2021/08/Specify-switch-statement-in-IDA-Pro/](https://www.nuke666.cn/2021/08/Specify-switch-statement-in-IDA-Pro/)