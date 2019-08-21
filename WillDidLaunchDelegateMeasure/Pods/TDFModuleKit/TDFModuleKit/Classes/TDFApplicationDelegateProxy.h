//
//  TDFApplicationDelegateProxy.h
//  Aspects
//
//  Created by tripleCC on 2017/10/23.
//

@import UIKit;

@interface TDFApplicationDelegateProxy : NSObject
@property (strong, nonatomic) id <UIApplicationDelegate> realDelegate;
@end
