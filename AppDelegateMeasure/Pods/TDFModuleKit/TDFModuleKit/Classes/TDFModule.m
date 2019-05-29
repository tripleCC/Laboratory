//
//  TDFModule.m
//  Aspects
//
//  Created by tripleCC on 2017/10/23.
//

#import "TDFModule.h"
#import "TDFModuleManager.h"

@implementation TDFModule
- (instancetype)init {
    if (self = [super init]) {
        if (![self conformsToProtocol:@protocol(TDFModuleProtocol)]) {
            @throw [NSException exceptionWithName:@"TDFModuleRegisterProgress" reason:@"subclass should confirm to <TDFModuleProtocol>." userInfo:nil];
        }
    }
    
    return self;
}

+ (instancetype)module {
    return [[self alloc] init];
}

+ (void)registerModule {
    // https://developer.apple.com/documentation/objectivec/nsobject/1418815-load?preferredLanguage=occ
    // In a custom implementation of load you can therefore safely message other unrelated classes from the same image, but any load methods implemented by those classes may not have run yet.
    // load 之前，同一个 image 中的所有 class 都是已知的，所以可以调用
    [TDFModuleManager addModuleClass:self];
}

+ (TDFModulePriority)priority {
    return TDFModulePriorityMedium;
}

- (void)runAfterMethodExecuted:(void (^)(void))block {
    // 当前代码执行完后，再执行 block 代码
    dispatch_async(dispatch_get_main_queue(), ^{
        !block ?: block();
    });
}

@end
