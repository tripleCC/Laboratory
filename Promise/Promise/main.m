//
//  main.m
//  Promise
//
//  Created by tripleCC on 6/27/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface A : NSObject

@end
@implementation A
@end
static A* a = nil;

static int my_static_int = 1;
int main(int argc, const char * argv[]) {
    @autoreleasepool {
       
        my_static_int = 1;
        // insert code here...
        NSLog(@"Hello, World!");
        
        
    }
    return 0;
}
