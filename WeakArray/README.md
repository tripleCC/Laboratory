弱引用集合有 NSPointerArray，NSMapTable，NSHashTable，对应强引用集合 NSArray、NSDictionary、NSSet 。	弱引用集合有两个特性： 

- 弱引用加入的对象
- 对象释放后会移除集合中对应的对象地址。

这里利用 NSMutableArray 简单实现下 NSPointerArray 的部分功能，有两个关键点：

- 使用 weak proxy 持有加入的对象，让 NSMutableArray 持有 weak proxy
- 给加入对象挂上关联对象，关联对象在释放时，执行从 NSMutableArray 中删除元素的回调 （对象释放时，会先执行关联对象的 dealloc ，再执行自身的 dealloc）

核心代码就一个添加方法，这个方法主要功能就是配置上面两个关键点：

```objc
- (void)addObject:(id)anObject {
    WAWeakItem *item = [[WAWeakItem alloc] initWithValue:anObject];
    
    void (^block)(void) = ^{
        @synchronized (self) { // anObject 可能在后台线程释放
            [self removeObject:item];
        }
    };
    
    WAReleaseHandler *handler = [anObject wa_releaseHandler];
    if (handler) {
        [handler addHandler:block];
    } else {
        [anObject setWa_releaseHandler:[[WAReleaseHandler alloc] initWithBlock:block]];
    }
    
    [_array addObject:item];
}
```