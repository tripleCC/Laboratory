//
//  TDFLeaksMonitor+Internal.h
//  TDFLeaksMonitor
//
//  Created by tripleCC on 7/11/19.
//

#ifndef TDFLeaksMonitor_Internal_h
#define TDFLeaksMonitor_Internal_h

#import "TDFLeaksMonitor.h"
#import "TDFLeakObjectInfo.h"

@interface TDFLeaksMonitor ()
- (void)detectLeaksForObject:(id <TDFLeakObjectProxyCollectable>)object;
@end

#endif /* TDFLeaksMonitor_Internal_h */
