//
//  TDFLeaksMonitor.h
//  TDFLeaksMonitor
//
//  Created by tripleCC on 7/2/19.
//

#import <Foundation/Foundation.h>
#import "TDFLeakObjectInfo.h"

NS_ASSUME_NONNULL_BEGIN

@protocol TDFLeaksMonitorDelegate <NSObject>
- (void)LeaksMonitorDidDetectLeakInfos:(TDFLeakObjectInfoGroup *)infoGroup;
@end

@class TDFLeakObjectProxyCollector;
@interface TDFLeaksMonitor : NSObject
@property (assign, nonatomic) NSTimeInterval delayMonitorInSeconds;

+ (instancetype)shared;
- (instancetype)init NS_UNAVAILABLE;

- (void)start;

- (void)addWhiteList:(NSArray <NSString *> *)whiteList;
- (void)addDelegate:(id <TDFLeaksMonitorDelegate>)delegate;
- (void)removeDelegate:(id <TDFLeaksMonitorDelegate>)delegate;
@end

NS_ASSUME_NONNULL_END
