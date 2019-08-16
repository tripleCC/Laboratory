# 聊聊循环引用的检测



Objective-C 使用引用计数作为 iPhone 应用的内存管理方案，引用计数相比 GC 更适用于内存不太充裕的场景，只需要收集与对象关联的局部信息来决定是否回收对象，而 GC 为了明确可达性，需要全局的对象信息。引用计数固然有其优越性，但也正是因为缺乏对全局对象信息的把控，导致 Objective-C 无法自动销毁陷入循环引用的对象。虽然 Objective-C 通过引入弱引用技术，让开发者可以尽可能地规避这个问题，但在引用层级过深，引用路径不那么直观的情况下，即使是经验丰富的工程师，也无法百分百保证产出的代码不存在循环引用。


<!--more-->

这时候就需要有一种检测方案，可以实时检测对象之间是否发生了循环引用，来辅助开发者及时地修正代码中存在的内存泄漏问题。要想检测出循环引用，最直观的方式是递归地获取对象强引用的其他对象，并判断检测对象是否被其路径上的对象强引用了，也就是在有向图中去找环。明确检测方式之后，接下来需要解决的是如何获取强引用链，也就是获取对象的强引用，尤其是最容易造成循环引用的 block。


## Block 捕获实体引用

> 往期关于 Block 的文章 [对 Block 的一点补充](https://triplecc.github.io/2019/04/14/Objective-CBlock%E8%A1%A5%E5%85%85/)、[用 Block 实现委托方法](https://triplecc.github.io/2017/07/28/2017-07-28-blockhe-nsmethodsignature/)、[Block技巧与底层解析](https://triplecc.github.io/2015/07/19/2015-08-27-blockji-qiao-yu-di-ceng-jie-xi/)

### 捕获区域布局初探

首先根据 block 的[定义结构](https://github.com/tripleCC/Laboratory/blob/d5d98d343a918d3883a2d5274da212cd44f50414/AppleSources/libclosure-73/Block_private.h#L216-L242)，可以简单地将其视为：

```objc
struct sr_block_layout {
    void *isa;
    int flags;
    int reserved;
    void (*invoke)(void *, ...);
    struct sr_block_descriptor *descriptor;
    /* Imported variables. */
};

// 标志位不一样，这个结构的实际布局也会有差别，这里简单地放在一起好阅读
struct sr_block_descriptor {
    unsigned long reserved; // Block_descriptor_1
    unsigned long size; // Block_descriptor_1
    void (*)(void *dst, void *src);  // Block_descriptor_2 BLOCK_HAS_COPY_DISPOSE
    void (*dispose)(void *); // Block_descriptor_2
    const char *signature; // Block_descriptor_3 BLOCK_HAS_SIGNATURE
    const char *layout; // Block_descriptor_3 contents depend on BLOCK_HAS_EXTENDED_LAYOUT
};
```
可以看到 block 捕获的变量都会存储在 sr_block_layout 结构体 descriptor 字段之后的内存空间中，下面我们通过 `clang -rewrite-objc` 重写如下代码语句 :

```objc
int i = 2;
^{
    i;
};
```
可以得到 : 

```c
struct __block_impl {
  void *isa;
  int Flags;
  int Reserved;
  void *FuncPtr;
};

struct __main_block_impl_0 {
  struct __block_impl impl;
  struct __main_block_desc_0* Desc;
  int i;
  ...
};
```

`__main_block_impl_0` 结构中新增了捕获的 i 字段，即 sr_block_layout 结构体的 imported variables 部分，这种操作可以看作在 sr_block_layout 尾部定义了一个 0 长数组，可以根据实际捕获变量的大小，给捕获区域申请对应的内存空间，只不过这一操作由编译器完成 :

```c
struct sr_block_layout {
    void *isa;
    int flags;
    int reserved;
    void (*invoke)(void *, ...);
    struct sr_block_descriptor *descriptor;
    char captured[0];
};
```

既然已经知道了捕获变量 i 的存放地址，那么我们就可以通过 `*(int *)layout->captured` 在运行时获取 i 的值。得到了捕获区域的起始地址之后，我们再来看捕获区域的布局问题，考虑以下代码块 :

```objc
int i = 2;
NSObject *o = [NSObject new];
void (^blk)(void) = ^{
    i;
    o;
};
```
捕获区域的布局分两部分看：顺序和大小，我们先使用老方法重写代码块 : 

```objc
struct __main_block_impl_0 {
  struct __block_impl impl;           // 24
  struct __main_block_desc_0* Desc;   // 8 指针占用内存大小和寻址长度相关，在 64 位机环境下，编译器分配空间大小为 8 字节
  int i;                              // 8
  NSObject *o;                        // 8
  ...
};
```
按照目前 clang 针对 64 位机的默认对齐方式（**下文的字节对齐计算都基于此前提条件**），可以计算出这个结构体占用的内存空间大小为 `24 + 8 + 8 + 8 = 48`字节，并且按照上方代码块先 i 后 o 的捕获排序方式，如果我要访问捕获的 o 对象指针变量，只需要在捕获区域起始地址上偏移 8 字节即可，我们可以借助 lldb 的 memory read (x) 命令查看这部分内存空间 :

```objc
(lldb) po *(NSObject **)(layout->captured + 8)
0x0000000000000002
(lldb) po *(NSObject **)layout->captured
<NSObject: 0x10073f290>
(lldb) p *(int *)(layout->captured + 8)
(int) $6 = 2
(lldb) p (int *)(layout->captured + 8)
(int *) $9 = 0x0000000100740d18
(lldb) p layout->descriptor->size
(unsigned long) $11 = 44
(lldb) x/44bx layout
0x100740cf0: 0x70 0x21 0x7b 0xa6 0xff 0x7f 0x00 0x00
0x100740cf8: 0x02 0x00 0x00 0xc3 0x00 0x00 0x00 0x00
0x100740d00: 0x40 0x1d 0x00 0x00 0x01 0x00 0x00 0x00
0x100740d08: 0xb0 0x20 0x00 0x00 0x01 0x00 0x00 0x00
0x100740d10: 0x90 0xf2 0x73 0x00 0x01 0x00 0x00 0x00
0x100740d18: 0x02 0x00 0x00 0x00
```
和使用 `clang -rewrite-objc` 重写时的猜想不一样，我们可以从以上终端日志中看出以下两点 :

- 捕获变量 i、o 在捕获区域的排序方式为 o、i，o 变量地址与捕获起始地址一致，i 变量地址为捕获起始地址加上 8 字节
- 捕获整形变量 i 在内存中实际占用空间大小为 4 字节

那么 block 到底是怎么对捕获变量进行排序，并且为其分配内存空间的呢？这就需要看 clang 是如何处理 block 捕获的外部变量了。

### 捕获区域布局分析

首先解决捕获变量排序的问题，根据 [clang 针对这部分的排序代码](https://github.com/llvm-mirror/clang/blob/e870496ea61feb01aa0eb4dc599be0ddf2d03878/lib/CodeGen/CGBlocks.cpp#L366-L384)，我们可以知道，在对齐字节数 (alignment) 不相等时，捕获的实体按照 alignment 降序排序 (C 结构体比较特殊，即使整体占用空间比指针变量大，也排在对象指针后面)，否则按照以下类型进行排序 :

1. `__strong` 修饰对象指针变量
2. `__block` 修饰对象指针变量
3. `__weak` 修饰对象指针变量
4. 其他变量
 
再结合 [clang 对捕获变量对齐子节数计算方式](https://github.com/llvm-mirror/clang/blob/e870496ea61feb01aa0eb4dc599be0ddf2d03878/lib/CodeGen/CGBlocks.cpp#L519-L775) ，我们可以知道，block 捕获区域变量的对齐结果趋向于被 `__attribute__ ((__packed__))` 修饰了的结构体，举个例子 :

```objc
struct foo {
    void *p;    // 8
    int i;      // 4
    char c;     // 4 实际用到的内存大小为 1
};
```
创建 foo 结构体需要分配的空间大小为 `8 + 4 + 4 = 16`，关于结构体的内存对齐方式，这里额外说几句，编译器会按照成员列表的顺序一个接一个地给每个成员分配内存，只有当存储成员需要满足正确的边界对齐要求时，成员之间才可能出现用于填充的额外内存空间，以提升计算机的访问速度（对齐标准一般和寻址长度一致），在声明结构体时，让那些对齐边界要求最严格的成员最先出现，对边界要求最弱的成员最后出现，可以最大限度地减少因边界对齐而带来的空间损失。再看以下代码块 :

```objc
struct foo {
    void *p;    // 8
    int i;      // 4
    char c;     // 1
} __attribute__ ((__packed__));
```
`__attribute__ ((__packed__))` 编译属性告诉编译器，按照字段的实际占用子节数进行对齐，所以创建 foo 结构体需要分配的空间大小为 `8 + 4 + 1 = 13`。

结合以上两点，我们可以尝试分析以下 block 捕获区域的变量布局情况 :

```objc
NSObject *o1 = [NSObject new];
__weak NSObject *o2 = o1;
__block NSObject *o3 = o1;
unsigned long long j = 4;
int i = 3;
char c = 'a';
void (^blk)(void) = ^{
    i;
    c;
    o1;
    o2;
    o3;
    j;
};
```
首先按照 aligment 排序，可以得到排序顺序为 `[o1 o2 o3] j i c `，再根据 `__strong`、`__block`、`__weak` 修饰符对 `o1 o2 o3` 进行排序，可得到最终结果 `o1[8] o3[8] o2[8] j[8] i[4] c[1] `。同样的，我们使用 lldb 的 x 命令验证分析结果是否正确 :

```objc
(lldb) x/69bx layout
0x10200d940: 0x70 0x21 0x7b 0xa6 0xff 0x7f 0x00 0x00
0x10200d948: 0x02 0x00 0x00 0xc3 0x00 0x00 0x00 0x00
0x10200d950: 0xf0 0x1b 0x00 0x00 0x01 0x00 0x00 0x00
0x10200d958: 0xf8 0x20 0x00 0x00 0x01 0x00 0x00 0x00
0x10200d960: 0xa0 0xf6 0x00 0x02 0x01 0x00 0x00 0x00  // o1
0x10200d968: 0x90 0xd9 0x00 0x02 0x01 0x00 0x00 0x00  // o3
0x10200d970: 0xa0 0xf6 0x00 0x02 0x01 0x00 0x00 0x00  // o2
0x10200d978: 0x04 0x00 0x00 0x00 0x00 0x00 0x00 0x00  // j
0x10200d980: 0x03 0x00 0x00 0x00 0x61                 // i c
(lldb) p o1
(NSObject *) $1 = 0x000000010200f6a0
```
可以看到，小端模式下，捕获的 o1 和 o2 指针变量值为 0x10200f6a0 ,对应内存地址为 0x10200d960 和 0x10200d970，而 o3 因为被 `__block`  修饰，编译器为 o3 捕获变量包装了一层 byref 结构，所以其值为 byref 结构的地址 0x102000d990 ，而不是 0x10200f6a0 ，捕获的 j 变量地址为 0x10200d978，i 变量地址为 0x10200d980，c 字符变量紧随其后。

### Descriptor 的 Layout 信息

经过上述的一系列分析，捕获区域变量的布局方式已经大致摸清了，接下来回过头看下 sr_block_descriptor 结构的 layout 字段是用来干嘛的。从字面上理解，这个字段很可能保存了 block 某一部分的内存布局信息，比如捕获区域的布局信息，我们依旧使用上文的最后一个例子，看看 layout 的值 :

```objc
(lldb) p layout->descriptor->layout
(const char *) $2 = 0x0000000000000111 ""
```
可以看到 layout 值为空字符串，并没有展示出任何直观的布局信息，看来要想知道 layout 是怎么运作的，还需要阅读这一部分的 [block 代码](https://github.com/tripleCC/Laboratory/blob/d5d98d343a918d3883a2d5274da212cd44f50414/AppleSources/libclosure-73/Block_private.h#L283-L314) 和 [clang 代码](https://github.com/llvm-mirror/clang/blob/e5d2fdc902b0fb4e0a8f5a7d549728e1f2a648ad/lib/CodeGen/CGObjCMac.cpp#L2614-L2865)，我们一步步地分析这两段代码里面隐藏的信息，这里贴出其中的部分代码和注释 :

```objc
// block
// Extended layout encoding.

// Values for Block_descriptor_3->layout with BLOCK_HAS_EXTENDED_LAYOUT
// and for Block_byref_3->layout with BLOCK_BYREF_LAYOUT_EXTENDED

// If the layout field is less than 0x1000, then it is a compact encoding 
// of the form 0xXYZ: X strong pointers, then Y byref pointers, 
// then Z weak pointers.

// If the layout field is 0x1000 or greater, it points to a 
// string of layout bytes. Each byte is of the form 0xPN.
// Operator P is from the list below. Value N is a parameter for the operator.

enum {
    ...
    BLOCK_LAYOUT_NON_OBJECT_BYTES = 1,    // N bytes non-objects
    BLOCK_LAYOUT_NON_OBJECT_WORDS = 2,    // N words non-objects
    BLOCK_LAYOUT_STRONG           = 3,    // N words strong pointers
    BLOCK_LAYOUT_BYREF            = 4,    // N words byref pointers
    BLOCK_LAYOUT_WEAK             = 5,    // N words weak pointers
    ...
};

// clang 
/// InlineLayoutInstruction - This routine produce an inline instruction for the
/// block variable layout if it can. If not, it returns 0. Rules are as follow:
/// If ((uintptr_t) layout) < (1 << 12), the layout is inline. In the 64bit world,
/// an inline layout of value 0x0000000000000xyz is interpreted as follows:
/// x captured object pointers of BLOCK_LAYOUT_STRONG. Followed by
/// y captured object of BLOCK_LAYOUT_BYREF. Followed by
/// z captured object of BLOCK_LAYOUT_WEAK. If any of the above is missing, zero
/// replaces it. For example, 0x00000x00 means x BLOCK_LAYOUT_STRONG and no
/// BLOCK_LAYOUT_BYREF and no BLOCK_LAYOUT_WEAK objects are captured.
```

首先要解释的是 inline 这个词，Objective-C 中有一种叫做 Tagged Pointer 的技术，它让指针保存实际值，而不是保存实际值的地址，这里的 inline 也是相同的效果，即让 layout 指针保存实际的编码信息。在 inline 状态下，使用十六进制中的一位表示捕获变量的数量，所以每种类型的变量最多只能有 15 个，此时的 layout 的值以 0xXYZ 形式呈现，其中 X、Y、Z 分别表示捕获 `__strong`、`__block`、`__weak` 修饰指针变量的个数，如果其中某个类型的数量超过 15 或者捕获变量的修饰类型不为这三种任何一个时，比如捕获的变量由 `__unsafe_unretained` 修饰，则采用另一种表示方式，这种方式下，layout 会指向一个字符串，这个字符串的每个字节以 0xPN 的形式呈现，并以 0x00 结束，P 表示变量类型，N 表示变量个数，需要注意的是，N 为 0 表示 P 类型有一个，而不是 0 个，也就是说实际的变量个数比 N 大 1。需要注意的是，捕获 int 等基础类型，不影响 layout 的呈现方式，layout 编码中也不会有关于基础类型的信息，除非需要基础类型的编码来辅助定位对象指针类型的位置，比如捕获含有对象指针字段的结构体。举几个例子 : 

```objc
unsigned long long j = 4;
int i = 3;
char c = 'a';
void (^blk)(void) = ^{
    i;
    c;
    j;
};
```

以上代码块没有捕获任何对象指针，所以实际的 descriptor 不包含 copy 和 dispose 字段，去除这两个字段后，再输出实际的布局信息，结果为空（0x00 表示结束），说明捕获一般基础类型变量不会计入实际的 layout 编码 :

```objc
(lldb) p/x (long)layout->descriptor->layout
(long) $0 = 0x0000000100001f67
(lldb) x/8bx layout->descriptor->layout
0x100001f67: 0x00 0x76 0x31 0x36 0x40 0x30 0x3a 0x38
```

接着尝试第一种 layout 方式 :

```objc
NSObject *o1 = [NSObject new];
__block NSObject *o3 = o1;
__weak NSObject *o2 = o1;
void (^blk)(void) = ^{
    o1;
    o2;
    o3;
};
```
以上代码块对应的 layout 值为 0x111 ，表示三种类型变量每种一个 :

```objc
(lldb) p/x (long)layout->descriptor->layout
(long) $0 = 0x0000000000000111
```
再尝试第二种 layout 方式 :

```objc
NSObject *o1 = [NSObject new];
__block NSObject *o3 = o1;
__weak NSObject *o2 = o1;
NSObject *o4 = o1;
... // 5 - 18
NSObject *o19 = o1;
void (^blk)(void) = ^{
    o1;
    o2;
    o3;
    o4;
    ... // 5 - 18
    o19;
};
```

以上代码块对应的 layout 值是一个地址 0x0000000100002f44 ，这个地址为编码字符串的起始地址，转换成十六进制后为 `0x3f 0x30 0x40 0x50 0x00 `，其中 P 为 3 表示 `__strong` 修饰的变量，数量为 `15(f) + 1 + 0 + 1 = 17` 个，P 为 4 表示 `__block` 修饰的变量，数量为 `0 + 1 = 1` 个， P 为 5 表示 `__weak` 修饰的变量，数量为 `0 + 1 = 1` 个 :

```objc
(lldb) p/x (long)layout->descriptor->layout
(long) $0 = 0x0000000100002f44
(lldb) x/8bx layout->descriptor->layout
0x100002f44: 0x3f 0x30 0x40 0x50 0x00 0x76 0x31 0x36
```

### 结构体对捕获布局的影响

由于结构体字段的布局顺序在声明时就已经确定了，无法像 block 构造捕获区域一样，按照变量类型、修饰符进行调整，所以如果结构体中有类型为对象指针的字段，就需要一些额外信息来计算这些对象指针字段的偏移量，需要注意的是，被捕获结构体的内存对齐信息和未捕获时一致，以寻址长度作为对齐基准，捕获操作并不会变更对齐信息。同样地，我们先尝试捕获只有基本类型字段的结构体 :

```objc
struct S {
    char c;
    int i;
    long j;
} foo;
void (^blk)(void) = ^{
  foo;
};
```

然后调整 descriptor 结构，输出 layout :

```objc
(lldb) x/8bx layout->descriptor->layout
0x100001f67: 0x00 0x76 0x31 0x36 0x40 0x30 0x3a 0x38
```
可以看到，只有含有基本类型的结构体，同样不会影响 block 的 layout 编码信息。接下来我们给结构体新增 `__strong` 和 `__weak` 修饰的对象指针字段 :

```objc
struct S {
    char c;
    int i;
    __strong NSObject *o1;
    long j;
    __weak NSObject *o2;
} foo;
void (^blk)(void) = ^{
  foo;
};
```
同样分析输出 layout :

```objc
(lldb) x/8bx layout->descriptor->layout
0x100002f47: 0x20 0x30 0x20 0x50 0x00 0x76 0x31 0x36
```
layout 编码为`0x20 0x30 0x20 0x50 0x00`，其中 P 为 2 表示 word 字类型（非对象），由于字大小一般和指针一致，所以这里表示占用了 8 * (N + 1) 个字节，第一个 0x20 表示非对象指针类型占用了 8 个字节，也就是 char 类型和 int 类型字段对齐之后所占用的空间，接着 0x30 表示有一个 `__strong` 修饰的对象指针字段，第二个 0x20 表示非对象指针 long 类型占用了 8 个字节，最后的 0x50 表示有一个 `__weak` 修饰的对象指针字段。由于编码中包含了每个字段的排序和大小，我们就可以通过解析 layout 编码后的偏移量，拿到想要的对象指针值。 P 还有个 byte 类型，值为 1 ，和 word 类型有相似的功能，只是表示的空间大小不同。


### Byref 结构的布局

由 `__block` 修饰地捕获变量，会先转换成 byref 结构，再由这个结构去持有实际的捕获变量，block 只负责管理 byref 结构。 

```objc
// 标志位不一样，这个结构的实际布局也会有差别，这里简单地放在一起好阅读
struct sr_block_byref {
    void *isa;
    struct sr_block_byref *forwarding;
    volatile int32_t flags; // contains ref count
    uint32_t size;
    // requires BLOCK_BYREF_HAS_COPY_DISPOSE
    void (*byref_keep)(struct sr_block_byref *dst, struct sr_block_byref *src);
    void (*byref_destroy)(struct sr_block_byref *);
    // requires BLOCK_BYREF_LAYOUT_EXTENDED
    const char *layout;
};
```
以上代码块就是 byref 对应的结构体。第一眼看上去，我比较困惑为什么还要有 layout 字段，虽然上文的 block 源码注释说明了 byref 和 block 结构一样，都具备两种不同的布局方式，但是 byref 不是只针对一个变量么，难道和 block 捕获区域一样也可以携带多个捕获变量？带着这个困惑，我们先看下以下表达式 :

```objc
__block  NSObject *o1 = [NSObject new];
```

使用 clang 重写之后 :

```objc
struct __Block_byref_o1_0 {
    void *__isa;
    __Block_byref_o1_0 *__forwarding;
    int __flags;
    int __size;
    void (*__Block_byref_id_object_copy)(void*, void*);
    void (*__Block_byre/* @autoreleasepool */o{ __AtAutoreleasePool __autoreleasepool; e)(void*);
    NSObject *o1;
};
```

和 block 捕获变量一样，byref 携带的变量也是保存在结构体尾部的内存空间里，当前上下文中，可以直接通过 sr_block_byref 的 layout 字段获取 o1 对象指针值。可以看到，在包装如对象指针这类常规变量时，layout 字段并没有起到实质性的作用，那什么条件下的 layout 才表示布局编码信息呢？如果使用 layout 字段表示编码信息，那么携带的变量又是何处安放的呢？我们一个个解答。

针对第一个问题，先看以下代码块 :

```objc
__block struct S {
    NSObject *o1;
} foo;
foo.o1 = [NSObject new];
void (^blk)(void) = ^{
  foo;
};
```

使用 clang 重写之后 :

```objc
struct __Block_byref_foo_0 {
  void *__isa;
  __Block_byref_foo_0 *__forwarding;
  int __flags;
  int __size;
  void (*__Block_byref_id_object_copy)(void*, void*);
  void (*__Block_byref_id_object_dispose)(void*);
  struct S foo;
};
```

和常规类型一样，foo 结构体保存在结构体尾部，也就是原本 layout 所在的字段，重写的代码中依然看不到 layout 的踪影，接着我们试着输出 foo :

```objc
(lldb) po foo.o1
<NSObject: 0x10061f130>
(lldb) p (struct S)a_byref->layout
error: Multiple internal symbols found for 'S'
(lldb) p/x (long)a_byref->layout
(long) $3 = 0x0000000000000100
(lldb) x/56bx a_byref
0x100627c20: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
0x100627c28: 0x20 0x7c 0x62 0x00 0x01 0x00 0x00 0x00
0x100627c30: 0x04 0x00 0x00 0x13 0x38 0x00 0x00 0x00
0x100627c38: 0x90 0x1b 0x00 0x00 0x01 0x00 0x00 0x00
0x100627c40: 0x00 0x1c 0x00 0x00 0x01 0x00 0x00 0x00
0x100627c48: 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00
0x100627c50: 0x30 0xf1 0x61 0x00 0x01 0x00 0x00 0x00
```
看来事情并没有看上去的那么简单，首先重写代码中 foo 字段所在内存保存的并不是结构体，而是 0x0000000000000100，这个 100 是不是看着有点眼熟，没错，这就是 byref 的 layout 信息，根据 0xXYZ 编码规则，这个值表示有 1 个 `__strong` 修饰的对象指针。接着针对第二个问题，携带的对象指针变量存在哪，我们把视线往下移动 8 个字节，这不就是 foo.o1 对象指针的值么。总结下，在存在 layout 的情况下，byref 使用 8 个字节保存 layout 编码信息，并紧跟着在 layout 字段后存储捕获的变量。

以上是 byref 的第一种 layout 布局方式，我们再尝试第二种 :

```objc
__block struct S {
    char c;
    NSObject *o1;
    __weak NSObject *o3;
} foo;
foo.o1 = [NSObject new];
void (^blk)(void) = ^{
  foo;
};
```
使用 clang 重写代码之后 :

```objc
struct __Block_byref_foo_0 {
  void *__isa;
__Block_byref_foo_0 *__forwarding;
 int __flags;
 int __size;
 void (*__Block_byref_id_object_copy)(void*, void*/* @autoreleasepool */c{ __AtAutoreleasePool __autoreleasepool; _byref
struct __main_block_impl_0 {
  struct __block_impl impl;
  struct __main_block_desc_0* Desc;
  __main_block_impl_0(void *fp, struct __main_block_desc_0 *desc, int flags=0) {
    impl.isa = &_NSConcreteStackBlock;
    impl.Flags = flags;
    impl.FuncPtr = fp;
    Desc = desc;
  }
};
```
emmmm ...，上面代码并不是粘贴错误，貌似 Rewriter 并不能很好地处理这种情况，看来又需要我们直接去看对应内存地址中的值了 :

```objc
(lldb) x/72bx a_byref
0x100755140: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
0x100755148: 0x40 0x51 0x75 0x00 0x01 0x00 0x00 0x00
0x100755150: 0x04 0x00 0x00 0x13 0x48 0x00 0x00 0x00
0x100755158: 0x10 0x1b 0x00 0x00 0x01 0x00 0x00 0x00
0x100755160: 0xa0 0x1b 0x00 0x00 0x01 0x00 0x00 0x00
0x100755168: 0x8d 0x3e 0x00 0x00 0x01 0x00 0x00 0x00
0x100755170: 0x00 0x5f 0x6b 0x65 0x79 0x00 0x00 0x00
0x100755178: 0xd0 0x6e 0x75 0x00 0x01 0x00 0x00 0x00
0x100755180: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
(lldb) x/8bx a_byref->layout
0x100003e8d: 0x20 0x30 0x50 0x00 0x53 0x52 0x4c 0x61
```
地址 0x100755168 中保存了 layout 编码字符串的地址 0x0000000100003e8d ，将此字符串转换成十六进制后为 `0x20 0x30 0x50 0x00` ，这些值的含义在结构体对捕获布局的影响一节中已经描述过，这里就不重复说明了。 

### 强引用对象的获取

目前我们已经知道了 block / byref 如何布局捕获区域内存，以及如何获取关键的布局信息，接下来我们就可以尝试获取 block 强引用的对象了，这里我把强引用的对象分成两部分 :

- 被 block 强引用
- 被 byref 结构强引用

只要获取这两部分强引用的对象，任务就算完成了，由于上文已经将整个原理脉络理清了，所以编写出可用的代码并不困难。这两部分都涉及到布局编码，我们先根据 layout 的编码方式，解析出捕获变量的类型和数量 :

```objc
SRCapturedLayoutInfo *info = [SRCapturedLayoutInfo new];
    
if ((uintptr_t)layout < (1 << 12)) {
    uintptr_t inlineLayout = (uintptr_t)layout;
    [info addItemWithType:SR_BLOCK_LAYOUT_STRONG count:(inlineLayout & 0xf00) >> 8];
    [info addItemWithType:SR_BLOCK_LAYOUT_BYREF count:(inlineLayout & 0xf0) >> 4];
    [info addItemWithType:SR_BLOCK_LAYOUT_WEAK count:inlineLayout & 0xf];
} else {
    while (layout && *layout != '\x00') {
        unsigned int type = (*layout & 0xf0) >> 4;
        unsigned int count = (*layout & 0xf) + 1;
        
        [info addItemWithType:type count:count];
        layout++;
    }
}
```

然后遍历 block 的布局编码信息，根据变量类型和数量，计算出对象指针地址偏移，然后获取对应的对象指针值 :

```objc
- (NSHashTable *)strongReferencesForBlockLayout:(void *)iLayout {
    if (!iLayout) return nil;
    
    struct sr_block_layout *aLayout = (struct sr_block_layout *)iLayout;
    const char *extenedLayout = sr_block_extended_layout(aLayout);
    _blockLayoutInfo = [SRCapturedLayoutInfo infoForLayoutEncode:extenedLayout];
    
    NSHashTable *references = [NSHashTable weakObjectsHashTable];
    uintptr_t *begin = (uintptr_t *)aLayout->captured;
    for (SRLayoutItem *item in _blockLayoutInfo.layoutItems) {
        switch (item.type) {
            case SR_BLOCK_LAYOUT_STRONG: {
                NSHashTable *objects = [item objectsForBeginAddress:begin];
                SRAddObjectsFromHashTable(references, objects);
                begin += item.count;
            } break;
            case SR_BLOCK_LAYOUT_BYREF: {
                for (int i = 0; i < item.count; i++, begin++) {
                    struct sr_block_byref *aByref = *(struct sr_block_byref **)begin;
                    NSHashTable *objects = [self strongReferenceForBlockByref:aByref];
                    SRAddObjectsFromHashTable(references, objects);
                }
            } break;
            case SR_BLOCK_LAYOUT_NON_OBJECT_BYTES: {
                begin = (uintptr_t *)((uintptr_t)begin + item.count);
            } break;
            default: {
                begin += item.count;
            } break;
        }
    }
    
    return references;
}
```

block 布局区域中的 byref 结构需要进行额外的处理，如果 byref 直接携带 `__strong` 修饰的变量，则不需要关心 layout 编码，直接从结构尾部获取指针变量值即可，否则需要和处理 block 布局区域一样，先得到布局信息，然后遍历这些布局信息，计算偏移量，获取强引用对象地址 :

```objc

- (NSHashTable *)strongReferenceForBlockByref:(void *)iByref {
    if (!iByref) return nil;
    
    struct sr_block_byref *aByref = (struct sr_block_byref *)iByref;
    NSHashTable *references = [NSHashTable weakObjectsHashTable];
    int32_t flag = aByref->flags & SR_BLOCK_BYREF_LAYOUT_MASK;
    
    switch (flag) {
        case SR_BLOCK_BYREF_LAYOUT_STRONG: {
            void **begin = sr_block_byref_captured(aByref);
            id object = (__bridge id _Nonnull)(*(void **)begin);
            if (object) [references addObject:object];
        } break;
        case SR_BLOCK_BYREF_LAYOUT_EXTENDED: {
            const char *layout = sr_block_byref_extended_layout(aByref);
            SRCapturedLayoutInfo *info = [SRCapturedLayoutInfo infoForLayoutEncode:layout];
            [_blockByrefLayoutInfos addObject:info];
            
            uintptr_t *begin = (uintptr_t *)sr_block_byref_captured(aByref) + 1;
            for (SRLayoutItem *item in info.layoutItems) {
                switch (item.type) {
                    case SR_BLOCK_LAYOUT_NON_OBJECT_BYTES: {
                        begin = (uintptr_t *)((uintptr_t)begin + item.count);
                    } break;
                    case SR_BLOCK_LAYOUT_STRONG: {
                        NSHashTable *objects = [item objectsForBeginAddress:begin];
                        SRAddObjectsFromHashTable(references, objects);
                        begin += item.count;
                    } break;
                    default: {
                        begin += item.count;
                    } break;
                }
            }
        } break;
        default: break;
    }
    
    return references;
}
```

完整代码我放到了 [BlockStrongReferenceObject](https://github.com/tripleCC/Laboratory/tree/master/BlockStrongReferenceObject)，代码并没有进行过很严格的测试，可能存在一些未处理的边界条件，需要尝试 / 讨论的同学可自取。

### 另一种强引用对象获取方式

上文通过将 block 的布局编码信息转化为对应字段的偏移量来获取强引用对象，这一节介绍另外一种比较取巧的方式，也是目前检测循环引用工具获取 block 强引用对象的常用方式，比如 facebook 的 [FBRetainCycleDetector](https://github.com/facebook/FBRetainCycleDetector) 。根据[这块功能对应的源码](https://github.com/facebook/FBRetainCycleDetector/blob/ecd369ed1e03eb22178199091fecdba6c9964189/FBRetainCycleDetector/Layout/Blocks/FBBlockStrongLayout.m#L29-L102)，此方式大致原理如下 :

- 获取 block 的 dispose 函数 （如果捕获了强引用对象，需要利用这个函数解引用）
- 构造一个 fake 对象，此对象由若干个扩展的 byref 结构 (对象) 组成，其个数由 block size 决定，即把 block 划分为若干个 8 字节内存区域，就像以下代码块一样 :

  ```objc
  struct S {
      NSObject *o1;
      NSObject *o2;
  };
  struct S s = {
      .o2 = [NSObject new]
  };
  void **fake = (void **)&s;
  // fake[1] 和 s.o2 是一样的
  ```

- 扩展的 byref 结构会重写 release 方法，只在此方法中设置强引用标识位，不执行原释放逻辑
- 将 fake 对象作为参数，调用 dispose 函数，dispose 函数会去 release 每个 block 强引用的对象，在这里这些强引用对象被替换成了我们的 byref 结构，所以我们可以通过它的强引用标识位判断 block 的哪块区域保存了强引用对象地址
- 遍历 fake 对象，保存所有强引用标志位被设置的 byref 结构对应索引，后面通过这个索引可以去 block 中找强引用指针地址
- 释放所有的 byref 结构
- 根据上面得到的索引，获取捕获变量偏移量，偏移量为索引值 * 8 字节 (指针大小) ，再根据偏移量去 block 内存块中拿强引用对象地址

关于这种方案，我们需要明确下面几个点。

首先这种方案也需要在明确 block 内存布局的情况下才能够实施，因为 block ，或者说 block 结构体，实际执行内存对齐时，并没有按照寻址大小也就是 8 字节对齐，假设 block 捕获区域的对齐方式变成了这样 :

```objc
struct __main_block_impl_0 {
  struct __block_impl impl;           // 24
  struct __main_block_desc_0* Desc;   // 8 指针占用内存大小和寻址长度相关，在 64 位机环境下，编译器分配空间大小为 8 字节
  int i;                              // 4    FakedByref 8
  NSObject *o1;                       // 8    FakedByref 8 [这里上个 FakedByref 后 4 个子节和当前 FakedByref 前 4 字节覆盖 o1 对象指针的 8 字节，导致 miss ]
  char c;                             // 1
  NSObject *o2;                       // 8
}
```
那么使用 fake 的方案就会失效，因为这种方案的前提是 block 内存对齐基准基于寻址长度，即指针大小。不过 block 对捕获的变量按照类型和尺寸进行了排序，`__strong` 修饰的对象指针都在前面，本来我们只需要这种类型的变量，并不关心其他类型，所以即使后面的对齐方式不满足 fake 条件也没关系，另外捕获结构体的对齐基准是基于寻址长度的，即使结构体有其他类型，也满足 fake 条件 :

```objc
struct __main_block_impl_0 {
  struct __block_impl impl;           // 24
  struct __main_block_desc_0* Desc;   // 8 指针占用内存大小和寻址长度相关，在 64 位机环境下，编译器分配空间大小为 8 字节
  NSObject *o1;                       // 8    FakedByref 8
  NSObject *o2;                       // 8    FakedByref 8
  int i;                              // 4    FakedByref 8
  char c;                             // 1        
}
```
可以看到，通过以上代码块的排序，让 o1 和 o2 都被 FakedByref 结构覆盖到了，而 i, c 变量本身就不会在 dispose 函数中访问，所以怎么设置都不会影响到策略的生效。

第二点是为什么要用扩展的 byref 结构，而不是随便整个重写了 release 的类过来，这是因为当 block 捕获了 `__block` 修饰的指针变量时，会将这个指针变量包装成 byref 结构，而 dispose 函数会对这个 byref 结构执行 `_Block_object_dispose` 操作，这个函数有两个形参，一个是对象指针，一个是 flag ，当 flag 指明对象指针为 byref 类型，而实际传入的实参不是，就会出现问题，所以这里必须用扩展的 byref 结构。

第三点是这种方式无法处理 `__block` 修饰对象指针的情况。

不过这种方式贵在简洁，无需考虑内部每种变量类型具体的布局方式，就可以满足大部分需要获取 block 强引用对象的场景。

## 对象成员变量强引用

对象强引用成员变量的获取相对来说直接些，因为每个对象对应的类中都有其成员变量的布局信息，并且 runtime 有现成的接口，只需要分析出编码格式，然后按顺序和成员变量匹配即可。获取编码信息的接口有两个， `class_getIvarLayout` 函数返回描述 strong ivar 数量和索引信的编码信息，相对的 `class_getWeakIvarLayout` 函数返回描述 weak ivar 的编码信息，这里基于前者进行分析。

`class_getIvarLayout` 返回值是一个 uint8 指针，指向一个字符串，uint8 在 16 进制下占用 2 位，所以编码以 2 位为一组，组内首位描述非 strong ivar 个数，次位为 strong ivar 个数，最后一组如果 strong ivar 个数为 0，则忽略，且 layout 以 0x00 结尾。下面举几个例子 :

```objc
// 0x0100
@interface A : NSObject {
    __strong NSObject *s1;
}
@end
```
起始非 strong ivar 个数为 0，并且接着一个 strong ivar ，得出编码为 0x01 。

```objc
// 0x0100
@interface A : NSObject {
    __strong NSObject *s1;
    __weak NSObject *w1;
}
@end
```
起始非 strong ivar 个数为 0，并且接着一个 strong ivar ，得出编码为 0x01，接着有个 weak ivar，但是后面没有 strong ivar 了，所以忽略。

```objc
// 0x011100
@interface A : NSObject {
    __strong NSObject *s1;
    __weak NSObject *w1;
    __strong NSObject *s2;
}
@end
```
起始非 strong ivar 个数为 0，并且接着一个 strong ivar ，得出编码为 0x01，接着有个 weak ivar，并且后面紧接着一个 strong ivar ，得出编码 0x11 ，合并得到 0x0111 。

```objc
// 0x211100
@interface A : NSObject {
    int i1;
    void *p1;
    __strong NSObject *s1;
    __weak NSObject *w1;
    __strong NSObject *s2;
}
@end
```
起始非 strong ivar 个数为 2，并且紧接着一个 strong ivar，得出编码 0x21，接着有个 weak ivar，后面紧接着一个 strong ivar ，得出编码 0x11 ，合并得到 0x2111 。

了解了成员变量的编码格式，剩下的就是如何解码并依次和成员变量进行匹配了，[FBRetainCycleDetector 已经实现了这部分功能](https://github.com/facebook/FBRetainCycleDetector/blob/ecd369ed1e03eb22178199091fecdba6c9964189/FBRetainCycleDetector/Layout/Classes/FBClassStrongLayout.mm#L97-L183) ，主要原理如下 :

- 获取所有的成员变量以及 ivar 编码
- 解析 ivar 编码，跳过非 strong ivar ，获得 strong ivar 所在索引值 (把对象分成若干个 8 字节内存片段)
- 利用 `ivar_getOffset` 函数获取 ivar 的偏移量，除以指针大小就是自身的索引值 (对象布局对齐基准为寻址长度，这里为 8 字节)
- 匹配 2、3 步获得的索引值，得到 strong ivar

当然 FBRetainCycleDetector 还实现了对结构体的处理，这块就不细究了。

## 小结

以上是我认为检测循环引用两个比较关键的点，特别是获取 block 捕获的强引用对象环节，block ABI 中并没有详细说明捕获区域布局信息，需要自己结合 block 源码以及 clang 生成 block 的 CodeGen 逻辑去推测实际的布局信息，所以得出的结论不一定正确，也欢迎感兴趣的同学和我交流。

## 参考

[Circle - a cycle collector for Objective-C ARC](https://github.com/mikeash/Circle/blob/master/Circle/CircleIVarLayout.m)

[FBRetainCycleDetector](https://github.com/facebook/FBRetainCycleDetector)

[Automatic memory leak detection on iOS](https://code.fb.com/ios/automatic-memory-leak-detection-on-ios/)

[Objective-C Class Ivar Layout 探索](https://blog.sunnyxx.com/2015/09/13/class-ivar-layout/)
