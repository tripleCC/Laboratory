//
//  AppDelegateMeasure.m
//  AppDelegateMeasure
//
//  Created by tripleCC on 5/29/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import "AppDelegateMeasure.h"

@implementation AppDelegateMeasure
+ (void)load {
    [self registerModule];
}

+ (TDFModulePriority)priority {
    return TDFModulePriorityVeryLow;
}

- (BOOL)application:(UIApplication *)application willFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    _beginWillLaunch = CFAbsoluteTimeGetCurrent();
    return YES;
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    [self runAfterMethodExecuted:^{
        self->_endDidLaunch = CFAbsoluteTimeGetCurrent();
        printf("\t\t Duration between will launch start and did launch end: %f milliseconds\n", (self->_endDidLaunch - self->_beginWillLaunch) * 1000);
    }];
    return YES;
}
@end
