//
//  Observable+Private.h
//  KVODataBinding
//
//  Created by tripleCC on 6/25/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#ifndef Observable_Private_h
#define Observable_Private_h

#import "Observable.h"
@interface Observable (Private)
@property (strong, nonatomic) Observable *source;
@end

#endif /* Observable_Private_h */
