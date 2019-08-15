//
//  main.m
//  BlockStrongReferenceObject
//
//  Created by tripleCC on 7/27/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//
#import <objc/runtime.h>
#import <Foundation/Foundation.h>
#import "SRBlockStrongReferenceCollector.h"

@interface Person : NSObject
+ (instancetype)personWithName:(NSString *)name;
@end
@implementation Person {
    NSString *_name;
}
+ (instancetype)personWithName:(NSString *)name {
    Person *p = [Person new];
    p->_name = name;
    return p;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@ %@", [super description], _name];
}
@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        __block  NSObject *o1 = [Person personWithName:@"o1"];
        __block NSObject *o3 = [Person personWithName:@"o3"];
        __block  NSObject *o2 = [Person personWithName:@"o2"];
        NSObject *o4 = [Person personWithName:@"o4"];
        __weak NSObject *o5 = [Person personWithName:@"o5"];;
        NSObject *o6 = [Person personWithName:@"o6"];
        NSObject *o7 = [Person personWithName:@"o7"];
        __weak NSObject *o8 = [Person personWithName:@"o8"];
        NSObject *o9 = [Person personWithName:@"o9"];
        NSObject *o10 = [Person personWithName:@"o10"];
        NSObject *o11 = [Person personWithName:@"o11"];
        __weak NSObject *o12 = [Person personWithName:@"o12"];
        long j = 4;
        int i = 3;
        char c = 'a';
         __block struct S {
            char c;
            int i;
            long j;
            NSObject *o1;
             __weak NSObject *o2;
            long iS;
            __block NSObject *o3;
        } foo;
        foo.o1 = [Person personWithName:@"S.o1"];
        void (^blk0)() = ^{};
        void (^blk)(void) = ^{
            blk0;
            j;
            i;
            c;
            foo;
            o1;
            o2;
            o3;
            o4;
            o5;
            o6;
            o7;
            o8;
            o9;
            o10;
            o11;
            o12;
        };
        blk();
        
        SRBlockStrongReferenceCollector *collector = [[SRBlockStrongReferenceCollector alloc] initWithBlock:blk];
        NSLog(@"%@", collector.block);
        NSLog(@"%@", collector.blockLayoutInfo);
        NSLog(@"%@", collector.blockByrefLayoutInfos);
        NSLog(@"%@", collector.strongReferences.allObjects);
        
    }
    return 0;
}


