//
//  ViewController.m
//  HookLoadMethods
//
//  Created by tripleCC on 5/21/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//
@import LoadHook;
#import "ViewController.h"


@interface B : NSObject
@end
@implementation B
@end
@implementation B (BC)
+ (void)load {
    sleep(1);
}
@end

@interface A : NSObject
@end
@implementation A
+ (void)load {
    sleep(2);
}

@end
@implementation A (AC)
+ (void)load {
    sleep(1);
}
@end

@implementation A (AC2)
+ (void)load {
    int k = 0;
    for (int i = 0; i < 1000000; i++) {
        for (int i = 0; i < 100; i++) {
            k++;
        }
    }
}
@end

@interface ViewController ()

@end
@implementation ViewController (V1)
+ (void)load {
    sleep(1);
}
@end
@implementation ViewController (V2)
+ (void)load {
    sleep(3);
}
@end
@implementation ViewController
+ (void)load {
    sleep(2);
}

- (void)viewDidLoad {
    [super viewDidLoad];
}
@end
