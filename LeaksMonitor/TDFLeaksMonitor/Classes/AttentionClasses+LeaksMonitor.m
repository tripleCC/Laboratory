//
//  Others+LeaksMonitor.m
//  Pods
//
//  Created by tripleCC on 7/8/19.
//

#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>
#import "TDFLeakObjectProxy.h"
#import "NSObject+LeaksMonitor.h"

@interface NSTimer (LeaksMonitor) <TDFLeakObjectProxyCollectable>
@end
@implementation NSTimer (LeaksMonitor)
- (BOOL)LeaksMonitor_objectCanBeIgnored {
    return NO;
}

- (BOOL)LeaksMonitor_objectCanBeCollected {
    return YES;
}
@end

@interface CADisplayLink (LeaksMonitor) <TDFLeakObjectProxyCollectable>
@end
@implementation CADisplayLink (LeaksMonitor)
- (BOOL)LeaksMonitor_objectCanBeIgnored {
    return NO;
}

- (BOOL)LeaksMonitor_objectCanBeCollected {
    return YES;
}
@end
