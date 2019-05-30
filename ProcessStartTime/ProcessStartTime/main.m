//
//  main.m
//  ProcessStartTime
//
//  Created by tripleCC on 5/30/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <sys/sysctl.h>
#include <mach/mach.h>

static NSTimeInterval getProcessStartTime(void) {
    struct kinfo_proc info;
    int pid = [[NSProcessInfo processInfo] processIdentifier];
    int cmd[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    size_t size = sizeof(info);
    
    if (!sysctl(cmd, sizeof(cmd) / sizeof(int), &info, &size, NULL, 0)) {
        struct timeval time = info.kp_proc.p_un.__p_starttime;
        return time.tv_sec * 1000.0 + time.tv_usec / 1000.0;
    }
    return 0;
}

NSTimeInterval getIntervalSinceStart(void) {
    return [[NSDate date] timeIntervalSince1970] * 1000 - getProcessStartTime();
}

int main(int argc, const char * argv[]) {
    printf("%f milliseconds\n", getIntervalSinceStart());
    
    return 0;
}
