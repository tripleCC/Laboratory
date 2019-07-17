//
//  TDFLeakObjectInfo.h
//  Pods-TDFLeaksMonitor_Example
//
//  Created by tripleCC on 7/9/19.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface TDFLeakObjectInfo : NSObject 
@property (weak, nonatomic, readonly) id leakObject;
@property (copy, nonatomic, readonly) NSString *leakName;
@property (copy, nonatomic, readonly) NSArray <NSString *> *traces;
@end

@interface TDFLeakObjectInfoGroup : NSObject
@property (copy, nonatomic, readonly) NSArray <TDFLeakObjectInfo *> *infos;
- (BOOL)addLeakObject:(id)leakObject traces:(NSArray <NSString *> *)traces;
@end

NS_ASSUME_NONNULL_END
