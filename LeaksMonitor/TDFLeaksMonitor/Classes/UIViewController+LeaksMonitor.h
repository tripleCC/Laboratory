//
//  UIViewController+LeaksMonitor.h
//  TDFLeaksMonitor
//
//  Created by tripleCC on 7/3/19.
//

#import <UIKit/UIKit.h>
#import "TDFLeakObjectProxy.h"

NS_ASSUME_NONNULL_BEGIN

@interface UIViewController (LeaksMonitor) <TDFLeakObjectProxyCollectable>
+ (void)LeaksMonitor_setup;
@end

NS_ASSUME_NONNULL_END
