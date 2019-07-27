//
//  UIViewController+AF.m
//  AF
//
//  Created by tripleCC on 7/26/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//
#import <objc/runtime.h>
#import "UIViewController+AF.h"

@implementation UIViewController (s_100ms)
+ (void)print {
    NSLog(@"AF");
}
+ (void)load {
    usleep(1000 * 100);
//    NSLog(@"s_100ms");
//    NSLog(@"AF UIViewController load");
}
@end

@interface NSObject (s_1_s)
@end
@implementation NSObject (s_1_s)
+ (void)load {
    sleep(1);
    NSLog(@"AF NSObject load");
}

@end
