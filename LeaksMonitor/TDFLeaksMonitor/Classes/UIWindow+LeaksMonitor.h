//
//  UIWindow+LeaksMonitor.h
//  TDFLeaksMonitor
//
//  Created by tripleCC on 7/11/19.
//

#import <OCHooking/OCHooking.h>

NS_ASSUME_NONNULL_BEGIN

@interface UIWindow (LeaksMonitor)
+ (void)LeaksMonitor_setup;
@end

NS_ASSUME_NONNULL_END
