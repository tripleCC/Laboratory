借助 KVO 技术，我们可以很方便地实现观察者模式，从而监听某个对象属性的变化：

```objective-c
self.d1 = [NSMutableDictionary dictionary];
self.d2 = [NSMutableDictionary dictionary];
__unused KVOObserver *kvo = [[KVOObserver alloc] initWithTarget:self.d1 keyPath:@"name" handler:^(id  _Nonnull new, id  _Nonnull old) {
self.d2[@"simpleName"] = new;
}];
self.d1[@"name"] = @"foo";
```
以上代码监听了 d1.name 字段的变更，并在变更回调中设置了 d2.simpleName，实现了 d1.name -> d2.simpleName 方向上的单向绑定，其中 KVOObserver 类为 KVO 接口的简单封装，只是把 target - action 回调模式桥接成 block 回调，并且在销毁时移除 KVO 监听者。可以看到，虽然这种简陋的代码也能实现绑定的功能，但是不够优雅，并且绑定逻辑复杂后也不利于代码的阅读。

绑定功能在响应式编程中比较常见，于是我们可以参考 RxSwift 和 ReactiveCocoa 等响应式框架的实现思路来改善编写体验。

先思考下双向绑定，双向绑定的任意一方即是观察者，也是被观察者，我们可以将它视为 ReactiveX 中的 Subject ，然后使用 Subject 来包装 KVO 。Subject 又表示热信号，除了主动发送数据外，其订阅者接收到的值取决于它订阅的时间，这点和 KVO 的性质相契合，观察者不会接收到设置监听回调前的那些变更信息。

首先要创建的是被观察者 Observable ，被观察者需要提供订阅功能，以让观察者对其进行监听：

```objective-c
@interface Observable : NSObject
- (void)subscribe:(void (^)(id value))block;
@end

- (void)subscribe:(void (^)(id value))block {
    [NSException raise:@"Abstract Method" format:@"Abstract Method"];
}
```
接着实现 Subject ，上面说了 Subject 也是被观察者，所以这里让它成为 Observable 的子类：

```objective-c
@interface KeyPathSubject : Observable
- (instancetype)initWithTarget:(id)target keyPath:(NSString *)keyPath;
@end

@implementation KeyPathSubject {
    __weak id _target;
    NSString *_keyPath;
    NSMutableArray *_handlers;
    KVOObserver *_observer;
}

#pragma mark - LifeCycle
- (instancetype)initWithTarget:(id)target keyPath:(NSString *)keyPath {
    if (self = [super init]) {
        _target = target;
        _keyPath = keyPath;
        _handlers = [NSMutableArray array];
        [self addObserver];
    }
    return self;
}

#pragma mark - Override
- (void)subscribe:(void (^)(id _Nonnull))block {    
    [_handlers addObject:block];
}

#pragma mark - Private
- (void)addObserver {
    __weak typeof(self) wself = self;
    _observer = [[KVOObserver alloc] initWithTarget:_target keyPath:_keyPath handler:^(id new, id old) {
        __strong typeof(wself) sself = wself;
        if ([new isEqual:old]) {
            return;
        }
        
        [sself doHandlers:new];
    }];
}

- (void)doHandlers:(id)value {
    for (void (^handler)(id) in _handlers) {
        handler(value);
    }
}
@end
```

需要注意的是 KeyPathSubject 通过对比 KVO 的新旧值是否相等来规避双向绑定的死循环，这种做法有其局限性。

通过以上封装，最初的单向绑定代码变成了这样：

```objective-c
KeyPathSubject *sub = [[KeyPathSubject alloc] initWithTarget:self.d1 keyPath:@"name"];
[sub subscribe:^(id value) {
    self.d2[@"simpleName"] = value;
}];
self.d1[@"name"] = @"foo";
```

假如 sub 在 d1.name 变更之前就释放了，那么 d2 将无法获得 d1 的变更值，所以这里还需要保持住 sub ，不让其提前释放，我们可以使用 DisposeBag 的方式管理 sub 的生命周期。使用 DisposeBag 需要在 subscribe 时返回一个 Disposable 对象，在 DisposeBag 释放时，它会执行名下所有 Disposable 的 dispose 方法以释放资源，比如 KeyPathSubject 的 subscribe :

```objective-c
- (Disposable *)subscribe:(void (^)(id _Nonnull))block {
    if (_disposed) {
        return nil;
    }
    
    [_handlers addObject:block];
    
    return [[Disposable alloc] initWithBlock:^{
        [self->_handlers removeObject:block];
    }];
}
```

上面 Disposable 实例的 dispose 方法会移除对应的观察闭包。同时由于闭包捕获了 KeyPathSubject 对象，使得此对象的生命周期和 DisposeBag 对象一致，以下代码就不会存在 sub 对象提前释放的问题：

```objective-c
- (void)initSubject {
    self.bag = [DisposeBag new];
    KeyPathSubject *sub = [[KeyPathSubject alloc] initWithTarget:self.d1 keyPath:@"name"];
    __weak typeof(self) wself = self;
    [[sub subscribe:^(id value) {
      wself.d2[@"simpleName"] = value;
    }] disposedBy:self.bag];  
}
- (void)onClick {
    self.d1[@"name"] = @"foo"; 
}
```

引入了 Observable 订阅机制后，我们可以很方便地实现对数据的流式处理，比如实现一个 Filter：

```objc
@interface Observable (Filter)
- (Observable *)filter:(BOOL(^)(id value))block;
@end

@interface ObservableFilter : Observable
- (instancetype)initWithSource:(Observable *)source filterBlock:(BOOL(^)(id value))block;
@end

@implementation Observable (Filter)
- (Observable *)filter:(BOOL(^)(id value))block {
    return [[ObservableFilter alloc] initWithSource:self filterBlock:block];
}
@end

@implementation ObservableFilter {
    BOOL(^_filterBlock)(id value);
}
- (instancetype)initWithSource:(Observable *)source filterBlock:(BOOL(^)(id value))block {
    if (self = [super init]) {
        self.source = source;
        _filterBlock = [block copy];
    }
    
    return self;
}

- (Disposable *)subscribe:(void (^)(id))block {
    [self.source subscribe:^(id value) {
        if (self->_filterBlock(value)) {
            block(value);
        }
    }];
}
@end
```

可以看到 Filter 也是一个 Observable，实现 Filter 的关键是让它持有上游的 Observable ，当外部向其订阅消息时，先执行上游 Observable 的 subscribe 方法，或者说自己创建一个订阅者去订阅上游 Observable，得到最终值再传递给外部订阅者。通过 Filter 我们就可以对数据流进行过滤：

```objective-c
KeyPathSubject *sub = [[KeyPathSubject alloc] initWithTarget:self.d1 keyPath:@"name"];
__weak typeof(self) wself = self;
[[[sub filter:^BOOL(id  _Nonnull value) {
    return [value hasPrefix:@"sim"];
}] subscribe:^(id value) {
    wself.d2[@"simpleName"] = value;
}] disposedBy:self.bag];
```

由于 KeyPathSubject 集观察者和被观察者的功能于一身，所以应该支持以下操作：

```objective-c
KeyPathSubject *s1 = [[KeyPathSubject alloc] initWithTarget:self.d1 keyPath:@"name"];
KeyPathSubject *s2 = [[KeyPathSubject alloc] initWithTarget:self.d2 keyPath:@"simple"];
[s1 bindTo:s2];
```

s2 成为了 s1 的观察者。我们可以让 KeyPathSubject 实现观察者协议，并在 doNext 中同步传入的值来实现以上操作：

```objective-c
@interface Observable (Binding)
- (Disposable *)bindTo:(id <ObserverProtocol>)observer;
@end

@implementation Observable (Binding)
- (Disposable *)bindTo:(id <ObserverProtocol>)observer {
    return [self subscribe:^(id  _Nonnull value) {
        [observer doNext:value];
    }];
}
@end

@interface KeyPathSubject : Observable <ObserverProtocol>
@end

@implementation KeyPathSubject 
- (void)doNext:(id)value {
    [_target setValue:value forKeyPath:_keyPath];
}
@end
```

