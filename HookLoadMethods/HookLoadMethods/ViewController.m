//
//  ViewController.m
//  HookLoadMethods
//
//  Created by tripleCC on 5/21/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//
#import "ViewController.h"
#import <objc/runtime.h>


@interface A : NSObject
@end
@implementation A
+ (void)load {
    usleep(100);
}

@end
@implementation A (sleep_100_ms)
+ (void)load {
    usleep(1000 * 100);
}
@end

@implementation A (copy_class_list)
+ (void)load {
    objc_copyClassList(nil);
}
@end

@interface B : NSObject
@end
@implementation B
@end
@implementation B (sleep_1_s)
+ (void)load {
    sleep(1);
}
@end


@interface ViewController ()

@end
@implementation ViewController (sleep_1_ms)
+ (void)load {
    usleep(1000);
}
@end
@implementation ViewController (sleep_50_ms)
+ (void)load {
    usleep(1000 * 50);
}
@end
@implementation ViewController
+ (void)load {
    NSLog(@"ViewController");
}

- (void)viewDidLoad {
    [super viewDidLoad];
}
@end
