//
//  TDFModuleManager.h
//  Aspects
//
//  Created by tripleCC on 2017/10/23.
//

@import Foundation;

@class TDFModule;
@class TDFApplicationDelegateProxy;

@interface TDFModuleManager : NSObject {
    @package
    TDFApplicationDelegateProxy *_proxy;
}
@property (strong, nonatomic, readonly) TDFApplicationDelegateProxy *proxy;
@property (strong, nonatomic, readonly) NSArray <TDFModule *> *modules;

+ (instancetype)shared;
+ (void)addModuleClass:(Class)cls;
+ (void)removeModuleClass:(Class)cls;
@end
