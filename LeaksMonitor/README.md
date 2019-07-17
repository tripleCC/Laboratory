我们在编写日常业务代码时，或多或少都会引入一些导致内存泄漏的代码，而这种行为又很难被监控，这就导致应用内存泄漏的口子越开越大，直接影响到线上应用的稳定性。虽然 Xcode 的 Instrucment 提供了 Leaks 和 Allocations 工具让我们能精准地定位内存泄漏问题，但是这种方式相对比较繁琐，需要开发人员频繁地去操作应用界面，以触发泄漏场景，所以 Leaks 和 Allocations 更加适合定期组织的大排查，作为监测手段，则显得笨重。



## 背景

对于内存泄漏的监测，业内已经有了两款成熟的开源工具，分别是 PLeakSniffer 和 MLeaksFinder。PLeakSniffer 使用 Ping-Pong 方式监测对象是否存活，在进入页面时，创建控制器关联的一系列对象代理，根据这些代理在控制器销毁时能否响应 Ping 判断代理对应的对象是否泄漏。MLeaksFinder 则是在控制器销毁时，延迟 3s 后再向监测对象发送消息，根据监测对象能否响应消息判断其是否泄漏。这两个方案基本能覆盖大部分对象泄漏或者延迟释放了的场景，考虑到性能损耗以及内存占用因素，我偏向于第二种方案。


下面说下在实际试用这两款工具后，我遇到的部分问题。

首先是 MLeaksFinder ：

- 没有处理集合对象
- 没有处理对象持有的属性
- 每个对象都触发 3s 延迟机制，没有缓存后统一处理
- 检测结果输出分散

然后是 PLeakSniffer ：

- 没有处理集合对象
- 处理对象持有属性时，系统类过滤不全面
- 处理对象持有属性时，通过 KVC 访问属性导致一些懒加载的触发
- 无法处理未添加到视图栈中的泄漏视图
- 检测结果输出分散

对于检测到泄漏对象的交互处理，两者都提供了终端 log 输出和 alert 提示功能，MLeaksFinder 甚至可以直接通过断言中断应用。这种提示在开发阶段尚可接受，但是在提测阶段，强交互会给测试人员造成困扰。至于为什么在提测阶段还要集成泄漏监测工具，主要有两个原因：

- 应用功能过多的情况下，开发人员无法兼顾到老页面，一些老页面的泄漏场景可以通过测试人员在测试时触发，收集之后再统一处理
- 在组件化开发环境下，开发人员可能并没有集成泄漏监测工具，这种情况下，需要在提测阶段统一收集没有解决的泄漏问题


所以我目前对于监测输出的诉求有两点：

- 开发时，通过终端日志提示开发者出现了内存泄漏
- 提测时，收集内存泄漏的信息并上传至效能后台，周会时统一分配处理

下面就针对这些调研和需求，打造一个符合自身业务场景的泄漏监测轮子。

## 监测入口

和 MLeaksFinder 一样，我选择延迟 3s 的机制来判断对象是否泄漏，但是实现的细节略有差别。

首先，监测入口变更为 `viewDidDisappear:` 方法，我们只需在控制器被父控制器中移除或者被 Dismissed 时，触发监测动作即可：

```objc
- (void)LeaksMonitor_viewDidDisappear:(BOOL)animated {
[self LeaksMonitor_viewDidDisappear:animated];

if (![self isMovingFromParentViewController] && ![self isBeingDismissed]) {
return;
}

[[TDFLeaksMonitor shared] detectLeaksForObject:self];
}
```

在我们的应用中，还有一种监测入口出现在变更根控制器时，由于直接设置根控制器不会触发 viewDidDisappear 方法，所以需要另外设置 ：

```objc
- (void)LeaksMonitor_setRootViewController:(UIViewController *)rootViewController {
if (self.rootViewController && ![self.rootViewController isEqual:rootViewController]) {
[[TDFLeaksMonitor shared] detectLeaksForObject:self.rootViewController];
}

[self LeaksMonitor_setRootViewController:rootViewController];
}
```

接着，为了能够统一处理控制器及其持有对象，我们可以像 PLeakSniffer 一样，给每个对象包装一层代理 ：

```objc
@interface TDFLeakObjectProxy : NSObject
// 持有 target 的对象弱引用
@property (weak, nonatomic) id host;
// 被 host 持有的对象弱引用
@property (weak, nonatomic, readonly) id target;
@end
```
只要 host 释放了而 target 没释放，则视 target 已泄漏，如果 host 未释放，则不检测 target。然后使用一个 collector 去收集这些对象对应的 proxy ，在收集完之后统一监测 collector 中的所有 proxy ，这样就可以在一个控制器监测完成后，统一上传监测出的泄漏点了 ：

```objc
- (void)detectLeaksForObject:(id <TDFLeakObjectProxyCollectable>)object {
// 收集控制器关联的所有 proxy
// 收集之后再统一处理，避免对每一个对象都进行 3s 检测
TDFLeakObjectProxyCollector *collector = [[TDFLeakObjectProxyCollector alloc] init];
TDFLeakContext *context = [[TDFLeakContext alloc] init];
context.host = object;

(void)[object LeaksMonitor_collectProxiesForCollector:collector withContext:context];

// 检测 3s 之后，collector 中的所有 proxy 是否正常
[self detectProxyCollector:collector];
}
```

## 收集对象信息

因为要对不同的类做特异化处理，所以这里我们先定义一个协议，通过这个协议中的 collect 方法去收集不同类实例化对象的 proxy ：

```objc
@protocol TDFLeakObjectProxyCollectable <NSObject>
/**
收集对象及其名下的所有成员变量对应的 proxy

@param collector 收集器，存储 proxy
@param ctx 上下文
*/
- (void)LeaksMonitor_collectProxiesForCollector:( TDFLeakObjectProxyCollector * _Nonnull )collector withContext:( TDFLeakContext * _Nullable )ctx;
@end
```

这里的关键点在于如何让 NSObject 实现此协议，主要有四个步骤 ：

- 过滤系统类调用
- 向 collector 添加封装的 proxy
- 循环遍历对象对应的非系统类 / 父类属性，找出 copy / strong 类型属性，并获取其对应的成员变量值
- 向收集的所有成员变量对象发送 collect 方法

NSObject 实现 collect 协议方法后，其子类就可以通过这个方法递归地收集名下需要监测的属性信息。比如对于集合类型 NSArray ，实现协议方法如下，表示收集自身和每个集合元素的信息，不过由于 NSArray 是系统类，所以其实例化对象并不会被收集进 collector ，如果要收集系统类的属性信息，只能通过让系统类实现协议并重载 collect 方法，手动向属性值发送 collect 消息实现，UIViewController 的 `childViewControllers`、`presentedViewController`、`view` 属性也同理 ：

```objc
- (void)LeaksMonitor_collectProxiesForCollector:(TDFLeakObjectProxyCollector *)collector withContext:(TDFLeakContext *)ctx {
[super LeaksMonitor_collectProxiesForCollector:collector withContext:ctx];

[self enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
if ([obj conformsToProtocol:@protocol(TDFLeakObjectProxyCollectable)]) {
[obj LeaksMonitor_collectProxiesForCollector:collector withContext:LM_CTX_D(ctx, @"contains")];
}
}];
}
```

需要注意的是，直接调用属性的 getter 方法获取属性值，可能会触发属性懒加载，导致出现意料之外的问题 (比如调用 UIViewController 的 view 会触发 viewDidLoad)，所以要通过 `object_getIvar` 去获取属性对应的成员变量值。当然，这种处理方式会导致无法收集某些没有对应成员变量值的属性，比如关联对象、控制器的 view 等属性，权衡利弊之后，我还是选择忽略这种属性的监测。

除了收集必要的对象信息之外，我还记录了监测对象的引用路径信息，也就是上面 `LM_CTX_D` 宏做的事情。有些情况下，对象的引用路径能帮助我们发现，路径上的哪些操作导致了对象的泄漏，特别是在网页上浏览泄漏信息时，如果只有泄漏对象类和引用泄漏对象类两个信息，脱离了对象泄漏时的上下文环境，会增加修复的难度。有了引用路径信息后，输出的泄漏信息如下 ：

```objc
[
O : TDFViewController.view->UIView.subviews->__NSArrayM(contains)->A.subviews->__NSArrayM(contains)->O
TDFViewController : TDFViewController.childViewControllers->TDFViewController
__NSCFTimer : TDFViewController.timer->__NSCFTimer
]

```

## 过滤系统类

系统类信息并不是我们应该关心的，过滤掉并不会影响到最终的监测结果。目前我尝试了两种方式来确定一个类是否为系统类：

- 通过类所在 NSBundle 的路径
- 通过类所在地址

先说第一种，这种方式逻辑较为简单，代码如下：

```objc
BOOL LMIsSystemClass(Class cls) {
NSBundle *bundle = [NSBundle bundleForClass:cls];
if ([bundle isEqual:[NSBundle mainBundle]]) {
return NO;
}

static NSString *embededDirPath;
if (!embededDirPath) {
embededDirPath = [[NSBundle mainBundle].bundleURL URLByAppendingPathComponent:@"Frameworks"].absoluteString;
}

return ![bundle.bundlePath hasPrefix:embededDirPath];
}
```
应用的主二进制文件，和开发者添加的 embeded frameworks 都会在固定的文件目录下，所以直接比对路径前缀即可。

接下来说说第二种，这种方式的实现步骤如下：

- 遍历所有的 image ，通过 image 的名称判断是否为系统 image
- 缓存所有系统 image 的起始位置，也就是 mach_header 的地址
- 判断类是否为系统类时，使用 dladdr 函数获取类所在 image 的信息，通过 dli_fbase 字段获取起始地址
- 比对 image 的起始地址得知是否为系统类

实际尝试下来后，发现第二种方式耗时会比第一种多，dladdr 函数占用了大部分时间（[内部会遍历所有 image 的开始结束地址，和传入的地址进行比对](https://github.com/tripleCC/Laboratory/blob/85fd397fa806deea12b78555ed7be6667c1dc238/AppleSources/dyld-635.2/src/dyld.cpp#L444-L455)），所以最终选择了第一种方式作为判断依据。

过滤系统类时，针对那种会自泄漏的对象，需要进行特殊处理，不予过滤。比如 NSTimer / CADisplayLink 对象的常见内存泄漏场景，除了 target 强引用控制器造成循环引用域外，还有一种是打破了循环引用但没有在控制器销毁时执行 `invalidate` 操作，因为 NSTimer 由 RunLoop 持有，不手动停止的情况下，就会造成泄漏。


## 局限性

基于延时的内存泄漏监测机制虽然适用于大部分视图、控制器和一般属性的泄漏场景，但是还有少部分情况，这种机制无法处理，比如单例对象和共享对象。

首先说下单例对象，假设有 singleton 属性，其 getter 方法返回 Singleton 单例，这时延时监测机制无法自动过滤这种情况，依然会认为 singleton 泄漏了。有一种检测属性返回值是否为单例的方法，就是向返回值对应类发送 init 或者 share 相关方法，通过方法返回值和属性返回值的对比结果来判断，但是事实上我们无法确定业务方的单例是否重写了 init，也无法获知具体的单例类方法，所以这种方案适用面比较局限。单例对象的处理，目前还是通过白名单的方式处理较为稳妥。

共享对象的应用场景就比较普遍了，比如现有 A，B 页面，A 页面持有模型 M ，在跳转至 B 页面时，会将 M 传递给 B ，B 强引用了 M ，当 B 销毁时， M 不会销毁，而 M 又是 B 某个属性的值，所以监测机制会判断 M 泄漏了，实际上 M 只是 A 传递给 B 的共享对象。在一个控制器做完检测就需要上传至效能后台的情况下，共享对象还没有很好的处理方法，后期考虑结合 FBRetainCycleDetector 查找泄漏对象的循环引用信息，然后一并上传至效能后台，方便排查这种情况。因为每次 pop 都使用 FBRetainCycleDetector 检测控制器会比较耗时、甚至会造成延迟释放和卡顿，所以先用延时机制找出潜在的泄漏对象，再使用 FBRetainCycleDetector 检测这些泄漏对象，能极大得减少需要处理的对象数量。最终网页呈现的效果如下：

![](https://github.com/tripleCC/tripleCC.github.io/raw/master/images/Snip20190717_1.png)



## 小结

像内存泄露这种问题，最好在应用初期就开始着手监测和解决，否则当应用功能代码逐渐增多后，回过头来处理这种问题费时费力，还是比较麻烦的。

本文基于 PLeakSniffer 和 MLeaksFinder 监测工具的基础上，结合团队业务情况，进行了一些的改造，添加了集合对象的处理、引用路径的记录、对象的统一检测等功能，优化了部分有问题的代码，在一定程度上提升了延时机制的可用性。

## 参考

[iOS内存泄漏自动检测工具PLeakSniffer](http://mrpeak.cn/blog/leak/)

[MLeaksFinder：精准 iOS 内存泄露检测工具](https://wereadteam.github.io/2016/02/22/MLeaksFinder/)

[MTHawkeye](<https://github.com/meitu/MTHawkeye>)
