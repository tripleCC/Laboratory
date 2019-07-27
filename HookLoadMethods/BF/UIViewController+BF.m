//
//  UIViewController+BF.m
//  BF
//
//  Created by tripleCC on 7/26/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import "UIViewController+BF.h"

@implementation UIViewController (s_2_)
+ (void)print {
    NSLog(@"BF");
}

+ (void)load {
    sleep(2);
//    NSLog(@"s_2_");
//    NSLog(@"BF load");
}
@end

@interface NSObject (s_10_ms)

@end
@implementation NSObject (s_10_ms)
+ (void)load {
    usleep(100 * 10);
    NSLog(@"BF NSObject load");
}

@end
