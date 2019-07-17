//
//  TDFLeaksMonitorUtils.m
//  TDFLeaksMonitor
//
//  Created by tripleCC on 7/11/19.
//

#include <string.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach/vm_types.h>
#import "TDFLeaksMonitorUtils.h"

struct lm_objc_property LMExpandProperty(objc_property_t property) {
    struct lm_objc_property m_property = {0};
    
    m_property.name = property_getName(property);
    m_property.attributes = property_getAttributes(property);
    
    if (m_property.name == NULL || m_property.attributes == NULL ||
        m_property.name[0] == '\0' || m_property.attributes[0] == '\0') {
        return m_property;
    }
    
    const char *pos = m_property.attributes;
    do {
        size_t len = strcspn(pos, ",");
        if (len == 1) {
            switch (*pos) {
                #define LM_POS_CASE(con, name) { \
                    case con: m_property.name = true; \
                    break; }
                LM_POS_CASE('R', is_readonly)
                LM_POS_CASE('C', is_copy)
                LM_POS_CASE('&', is_strong)
                LM_POS_CASE('W', is_weak)
                LM_POS_CASE('N', is_nonatomic)
                LM_POS_CASE('D', is_dynamic)
                default: break;
            }
        } else if (len > 1) {
            switch (*pos) {
                #define LM_CPY_CASE(con, name)  \
                    case con: { \
                    strncpy(m_property.name, pos + 1, len - 1); \
                    m_property.name[len] = '\0'; \
                    break; }
                LM_CPY_CASE('V', ivar_name)
                LM_CPY_CASE('T', type_name)
                default: break;
            }
        }
        pos += len;
    } while (*pos++);
    
    return m_property;
}

BOOL LMIsSystemClass(Class cls) {
    NSBundle *bundle = [NSBundle bundleForClass:cls];
    if ([bundle isEqual:[NSBundle mainBundle]]) {
        return NO;
    }
    
    static NSString *embededDirPath;
    if (!embededDirPath) {
        embededDirPath = [[NSBundle mainBundle].bundleURL URLByAppendingPathComponent:@"Frameworks"].absoluteString;
    }
    
    return ![bundle.bundlePath hasPrefix:embededDirPath];
}

static bool lm_is_system_image(const char *imageName) {
    return ((!strncmp(imageName, "/Users/", 7) || !strncmp(imageName, "/private/var/", 13)) &&
            !strstr(imageName, "libswift")) ||
    !strncmp(imageName, "/var/", 5);
}

static const vm_address_t *lm_get_custom_image_addresses(unsigned int *outCount) {
    static vm_address_t *custom_image_addresses = NULL;
    static unsigned int custom_image_count = 0;
    
    if (!custom_image_addresses) {
        unsigned int count = _dyld_image_count();
        vm_address_t *image_addresses = malloc(sizeof(vm_address_t) * count);
        
        for (unsigned int i = 0; i < count; i++) {
            const char *name = _dyld_get_image_name(i);
            
            if (lm_is_system_image(name)) {
                const struct mach_header *mhdr = _dyld_get_image_header(i);
                image_addresses[custom_image_count++] = (vm_address_t)mhdr;
            }
        }
        
        size_t custom_size = sizeof(vm_address_t) * (custom_image_count);
        custom_image_addresses = malloc(custom_size);
        memcpy(custom_image_addresses, image_addresses, custom_size);
        free(image_addresses);
    }
    
    if (outCount) {
        *outCount = custom_image_count;
    }
    
    return custom_image_addresses;
}

static void *lm_get_image_base_containing_address(vm_address_t address) {
    Dl_info info = {0};
    // 这个操作耗时居然比 NSBundle 查询长
    if (!dladdr((void *)address, &info)) {
        return NULL;
    }
    
    return info.dli_fbase;
}

__unused static bool lm_is_address_in_custom_image(vm_address_t address) {
    unsigned int count = 0;
    const vm_address_t *image_addresses = lm_get_custom_image_addresses(&count);
    vm_address_t image_base = (vm_address_t)lm_get_image_base_containing_address(address);
    
    for (unsigned int i = 0; i < count; i++) {
        vm_address_t image_address = image_addresses[i];
        if (image_address == image_base) {
            return true;
        }
    }
    
    return false;
}
