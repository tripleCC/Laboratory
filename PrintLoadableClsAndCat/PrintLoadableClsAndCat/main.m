//
//  main.m
//  PrintLoadableClsAndCat
//
//  Created by tripleCC on 5/20/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "PrintLoadableClsAndCat.h"

@interface A : NSObject
@end
@implementation A
+ (void)load { }
@end

@implementation A (ACategory)
+ (void)load { }
@end

int main(int argc, const char * argv[]) {
    pl_print_loadable_clss_and_cats(main);
    return 0;
}
