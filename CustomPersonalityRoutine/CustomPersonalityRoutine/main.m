//
//  main.m
//  CustomPersonalityRoutine
//
//  Created by songruiwang on 2023/5/31.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"

void CALL_WITH_EH_FRAME(void (^block)(void));

int main(int argc, char * argv[]) {
  
  @try {
    CALL_WITH_EH_FRAME(^{
      @throw [NSException exceptionWithName:@"Exception" reason:nil userInfo:nil];
    });
  } @catch (NSException *exception) {
    // unreachable
  }
  
  NSString * appDelegateClassName;
  @autoreleasepool {
      // Setup code that might create autoreleased objects goes here.
      appDelegateClassName = NSStringFromClass([AppDelegate class]);
  }
  return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
