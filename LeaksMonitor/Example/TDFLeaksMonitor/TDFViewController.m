//
//  TDFViewController.m
//  TDFLeaksMonitor
//
//  Created by tripleCC on 07/02/2019.
//  Copyright (c) 2019 tripleCC. All rights reserved.
//
#import <objc/runtime.h>
#import "TDFViewController.h"


@interface O : UIView
@property (strong, nonatomic) void (^blk)();
@end

@implementation O
- (instancetype)init
{
    self = [super init];
    if (self) {
        _blk = ^{
            self;
        };
    }
    return self;
}
@end


@interface A : UIView
//@property (strong, nonatomic) void (^blk)();
//@property (strong, nonatomic) O *o;
@end

@implementation A
- (instancetype)init
{
    self = [super init];
    if (self) {
        [self addSubview:[O new]];
    }
    return self;
}
@end

@interface B : UIView
@property (strong, nonatomic) A *a;
@property (strong, nonatomic) TDFViewController *vc;
@end

@implementation B
- (instancetype)init
{
    self = [super init];
    if (self) {
        _a = [A new];
//        _vc = [TDFViewController new];
        
    }
    return self;
}
@end


@interface TDFViewController ()

@property (strong, nonatomic) void (^blk)(void);
@property (strong, nonatomic) B *b;

@property (strong, nonatomic) NSMutableArray *array;

@property (strong, nonatomic) NSMutableSet *set;

@property (strong, nonatomic) NSMutableDictionary *dic;
@property (strong, nonatomic) NSTimer *timer;
@end

struct KK {
    bool a;
    bool b;
    
};

@implementation TDFViewController

//- (void)setB:(B *)b {
//    objc_setAssociatedObject(self, _cmd, b, OBJC_ASSOCIATION_RETAIN);
//}
//
//- (B *)b {
//    return objc_getAssociatedObject(self, @selector(setB:));
//}
//- (instancetype)init
//{
//    self = [super init];
//    if (self) {
//        _blk = ^{
//            self;
//        };
//    }
//    return self;
//}
- (void)viewDidLoad
{
    [super viewDidLoad];
//    _set = [NSMutableSet set];
    _dic = @{}.mutableCopy;
//    [_set addObject:[B new]];
    _dic[@"1"] = [B new];
    
    _array = @[].mutableCopy;
    [_array addObject:[B new]];
    TDFViewController *vc = [TDFViewController new];
    vc.blk = ^{
        vc;
    };
    
    for (int i = 0; i < 10000; i++) {
        [self.view addSubview:[A new]];
    }
    [self addChildViewController:vc];
//    _array = [NSMutableArray array];
//    _b = [B new];
    _timer = [NSTimer scheduledTimerWithTimeInterval:4 repeats:YES block:^(NSTimer * _Nonnull timer) {
//        NSLog(@"=========");
    }];
    B *b = [B new];
    [self.view addSubview:b];
//
//    [self setB:[B new]];
//    [self.view addSubview:[B new]];
//    [_array addObject:_b];
//    NSLog(@"%@", [NSBundle mainBundle].bundlePath);
    
//    NSLog(@"%d \n %@", [clsBundle isEqual:[NSBundle mainBundle]] ||
//          [clsBundle.bundlePath hasPrefix:embededDir], embededDir);
    
//    NSLog(@"%@", [NSBundle allFrameworks]);
    
    if (self.navigationController.viewControllers.count > 1) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self.navigationController popViewControllerAnimated:YES];
        });
    } else {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            
            [self.navigationController pushViewController:[TDFViewController new] animated:NO];
        });
    }
    
//    _blk = ^{
//        self;
//    };
    
//    [self addChildViewController:[UIViewController new]];
//    [self LeaksMonitor_collectProxiesForCollector:nil];
	// Do any additional setup after loading the view, typically from a nib.
//    NSLog(@"===========");
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}
- (IBAction)click:(id)sender {
    [UIApplication sharedApplication].delegate.window.rootViewController = [TDFViewController new];
}

@end
