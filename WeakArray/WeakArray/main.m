//
//  main.m
//  WeakArray
//
//  Created by tripleCC on 8/16/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "WAWeakArray.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        WAWeakArray *wa = [WAWeakArray new];
        @autoreleasepool {
            NSObject *o = [NSObject new];
            NSObject *o1 = [NSObject new];
            [wa addObject:o];
            [wa addObject:o];
            [wa addObject:o1];
            for (id o in wa) {
                NSLog(@"%@", o);
            }
        }
        NSLog(@"%@", wa);
    }
    return 0;
}
