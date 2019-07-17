//
//  NSArray+LeaksMonitor.h
//  TDFLeaksMonitor
//
//  Created by tripleCC on 7/3/19.
//

#import <Foundation/Foundation.h>
#import "TDFLeakObjectProxy.h"

NS_ASSUME_NONNULL_BEGIN

@interface NSArray (LeaksMonitor) <TDFLeakObjectProxyCollectable>

@end

NS_ASSUME_NONNULL_END
