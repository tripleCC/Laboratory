//
//  TDFLeakObjectInfo.m
//  Pods-TDFLeaksMonitor_Example
//
//  Created by tripleCC on 7/9/19.
//

#import "TDFLeakObjectInfo.h"

@implementation TDFLeakObjectInfo
- (instancetype)initWithLeakObject:(id)leakObject leakName:(NSString *)leakName traces:(NSArray <NSString *> *)traces {
    if (self = [super init]) {
        _leakObject = leakObject;
        _leakName = leakName;
        _traces = traces;
    }
    
    return self;
}

- (NSString *)description {
    NSString *traces = [_traces componentsJoinedByString:@"->"];
    return [NSString stringWithFormat:@"%@ : %@", _leakName, traces];
}

@end

@implementation TDFLeakObjectInfoGroup {
    NSMutableDictionary *_infoMap;
}

- (instancetype)init {
    if (self = [super init]) {
        _infoMap = [NSMutableDictionary dictionary];
    }
    return self;
}

- (BOOL)addLeakObject:(id)leakObject traces:(NSArray<NSString *> *)traces {
    NSString *leakName = NSStringFromClass([leakObject class]);
    
    // 知道 leakName, 并且能去修复泄漏即可, 不需要记录所有路径, 即使 traces 不一样
    if (_infoMap[leakName]) {
        return NO;
    }
    
    TDFLeakObjectInfo *info = [[TDFLeakObjectInfo alloc] initWithLeakObject:leakObject leakName:leakName traces:traces];
    _infoMap[leakName] = info;
    
    return YES;
}

- (NSArray *)infos {
    return _infoMap.allValues;
}

- (NSString *)description {
    NSString *infos = [self.infos componentsJoinedByString:@"\n\t"];
    return [NSString stringWithFormat:@"\nPossible leak objects : [\n\t%@\n]", infos];
}
@end
