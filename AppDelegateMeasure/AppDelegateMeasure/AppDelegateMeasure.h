//
//  AppDelegateMeasure.h
//  AppDelegateMeasure
//
//  Created by tripleCC on 5/29/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <TDFModuleKit/TDFModuleKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface AppDelegateMeasure : TDFModule <TDFModuleProtocol>
@property (assign, nonatomic, readonly) CFAbsoluteTime beginWillLaunch;
@property (assign, nonatomic, readonly) CFAbsoluteTime endDidLaunch;
@end

NS_ASSUME_NONNULL_END
