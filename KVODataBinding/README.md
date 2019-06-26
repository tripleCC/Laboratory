

借助 KVO 技术，我们可以很方便地实现观察者模式，从而监听某个对象属性的变化

```objective-c
self.d1 = [NSMutableDictionary dictionary];
self.d2 = [NSMutableDictionary dictionary];
__unused KVOObserver *kvo = [[KVOObserver alloc] initWithTarget:self.d1 keyPath:@"name" handler:^(id  _Nonnull new, id  _Nonnull old) {
self.d2[@"simpleName"] = new;
}];
self.d1[@"name"] = @"foo";
```
以上代码监听了 d1.name 字段的变更，并在变更回调中设置了 d2.simpleName，实现了 d1.name -> d2.simpleName 方向上的单向绑定，其中 KVOObserver 类为 KVO 接口的简单封装，只是把 target - action 回调模式桥接成 block 回调，并且在销毁时移除 KVO 监听者。

可以看到，虽然这种简陋的代码也能实现绑定的功能，但是不够优雅，并且绑定逻辑复杂后也不利于代码的阅读。


