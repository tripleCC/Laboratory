//
//  TDFLeaksMonitorUtils.h
//  TDFLeaksMonitor
//
//  Created by tripleCC on 7/11/19.
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

NS_ASSUME_NONNULL_BEGIN

typedef struct lm_objc_property {
    const char *name;
    const char *attributes;
    bool is_strong;
    bool is_copy;
    bool is_weak;
    bool is_readonly;
    bool is_nonatomic;
    bool is_dynamic;
    char ivar_name[512];
    char type_name[218];
} *lm_objc_property_t;

CF_EXPORT struct lm_objc_property LMExpandProperty(objc_property_t property);
CF_EXPORT BOOL LMIsSystemClass(Class cls);

NS_ASSUME_NONNULL_END
