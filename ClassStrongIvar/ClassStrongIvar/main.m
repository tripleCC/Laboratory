//
//  main.m
//  ClassStrongIvar
//
//  Created by tripleCC on 8/16/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "CSStrongReferenceCollector.h"

@interface Person : NSObject {
    @public
    Person *_p1;
    int _i;
    Person *_p2;
}
@property (strong, nonatomic) Person *p3;
@property (weak, nonatomic) Person *p4;
@property (unsafe_unretained, nonatomic) Person *p5;
- (instancetype)initWithName:(NSString *)name;
@end

@implementation Person {
    NSString *_name;
}
- (instancetype)initWithName:(NSString *)name {
    if (self = [super init]) {
        _name = name;
    }
    return self;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@ %@", [super description], _name];
}
@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        Person *p = [Person new];
        p->_p1 = [[Person alloc] initWithName:@"p1"];
        p->_p2 = [[Person alloc] initWithName:@"p2"];
        p.p3 = [[Person alloc] initWithName:@"p3"];
        p.p4 = [[Person alloc] initWithName:@"p4"];
        p.p5 = [[Person alloc] initWithName:@"p5"];
        
        CSStrongReferenceCollector *collector = [[CSStrongReferenceCollector alloc] initWithObject:p];
        NSLog(@"%@", collector.strongReferences);
    }
    return 0;
}
