//
//  ViewController.m
//  AutoInvalidateTimer
//
//  Created by tripleCC on 6/19/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//
#import <objc/runtime.h>
#import "ViewController.h"
#import "AITimerTargetWrapper.h"


@interface ViewController () {
}

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    if (self.navigationController.viewControllers.count > 1) {
        AITimerTargetWrapper *targetWrapper = [[AITimerTargetWrapper alloc] initWithTarget:self];
        [NSTimer scheduledTimerWithTimeInterval:1 target:targetWrapper selector:@selector(test:) userInfo:nil repeats:YES];
    }

    // Do any additional setup after loading the view.
}

- (void)test:(NSTimer *)timer {
    NSLog(@"%@", @"asdfkasdhf");
}

@end
