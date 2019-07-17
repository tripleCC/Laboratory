//
//  TDFAppDelegate.h
//  TDFLeaksMonitor
//
//  Created by tripleCC on 07/02/2019.
//  Copyright (c) 2019 tripleCC. All rights reserved.
//

@import UIKit;

@protocol TDFLeaksMonitorDelegate;
@interface TDFAppDelegate : UIResponder <UIApplicationDelegate, TDFLeaksMonitorDelegate>

@property (strong, nonatomic) UIWindow *window;

@end
