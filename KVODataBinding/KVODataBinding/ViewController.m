//
//  ViewController.m
//  KVODataBinding
//
//  Created by tripleCC on 6/25/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import "ViewController.h"
#import "KeyPathSubject.h"
#import "Observable.h"
#import "DisposeBag.h"
#import "Protocols.h"
#import "Observable+Binding.h"
#import "Observable+Map.h"
#import "Observable+Filter.h"
#import "Observable+Just.h"
#import "KVOObserver.h"

@interface ViewController ()
@property (strong, nonatomic) NSString *name;
@property (strong, nonatomic) NSString *simple;
@property (strong, nonatomic) DisposeBag *bag;
@property (strong, nonatomic) KeyPathSubject *subject;

@property (strong, nonatomic) NSMutableDictionary *d1;
@property (strong, nonatomic) NSMutableDictionary *d2;
@end

@implementation ViewController {
    
}
- (IBAction)click2:(id)sender {
    self.d1[@"name"] = [NSString stringWithFormat:@"%ld", random()];
}

- (IBAction)click:(id)sender {
    self.d2[@"simple"] = [NSString stringWithFormat:@"%ld", random()];
}

- (void)viewDidLoad {
    [super viewDidLoad];
  
    self.d1 = [NSMutableDictionary dictionary];
    self.d2 = [NSMutableDictionary dictionary];
    __unused KVOObserver *kvo = [[KVOObserver alloc] initWithTarget:self.d1 keyPath:@"name" handler:^(id  _Nonnull new, id  _Nonnull old) {
        self.d2[@"simpleName"] = new;
    }];
    self.d1[@"name"] = @"foo";
    
    NSLog(@"%@", self.d2);
//
//    self.bag = [DisposeBag new];
//
//    __weak typeof(self) wself = self;
//    KeyPathSubject *s1 = [[KeyPathSubject alloc] initWithTarget:self.d1 keyPath:@"name"];
//    KeyPathSubject *s2 = [[KeyPathSubject alloc] initWithTarget:self.d2 keyPath:@"simple"];
//
//    [s1 bind:s2];
//
//    [[s1 subscribe:^(id  _Nonnull value) {
////        NSLog(@"1 %@ %@", wself.d2, wself.d1);
//    }] disposedBy:self.bag];
//
//    [[s2 subscribe:^(id  _Nonnull value) {
////        NSLog(@"2 %@ %@", wself.d2, wself.d1);
//    }] disposedBy:self.bag];
//
//    [[[s1 filter:^BOOL(id  _Nonnull value) {
//        return YES;//[value integerValue] % 2;
//    }] subscribe:^(id value) {
//        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
//            NSLog(@"3 %@ %@", wself.d2, wself.d1);
//        });
//    }] disposedBy:self.bag];
//
//    [[Observable just:@1] subscribe:^(id value) {
//        NSLog(@"%@", value);
//    }];
}
@end
