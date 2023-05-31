//
//  Personality.cpp
//  CustomPersonalityRoutine
//
//  Created by songruiwang on 2023/5/31.
//
#include <iostream>
#include <thread>
#include <cstdlib>
#include <map>
#include <unistd.h>
#include <stdint.h>
#include <unwind.h>
#include <exception>

#include "Personality.hpp"


struct __cxa_exception {
#if defined(__LP64__) || defined(_WIN64) || defined(_LIBCXXABI_ARM_EHABI)
    // Now _Unwind_Exception is marked with __attribute__((aligned)),
    // which implies __cxa_exception is also aligned. Insert padding
    // in the beginning of the struct, rather than before unwindHeader.
    void *reserve;

    // This is a new field to support C++ 0x exception_ptr.
    // For binary compatibility it is at the start of this
    // struct which is prepended to the object thrown in
    // __cxa_allocate_exception.
    size_t referenceCount;
#endif

    //  Manage the exception object itself.
    std::type_info *exceptionType;
    void (*exceptionDestructor)(void *);
    std::unexpected_handler unexpectedHandler;
    std::terminate_handler  terminateHandler;

    __cxa_exception *nextException;

    int handlerCount;

#if defined(_LIBCXXABI_ARM_EHABI)
    __cxa_exception* nextPropagatingException;
    int propagationCount;
#else
    int handlerSwitchValue;
    const unsigned char *actionRecord;
    const unsigned char *languageSpecificData;
    void *catchTemp;
    void *adjustedPtr;
#endif

#if !defined(__LP64__) && !defined(_WIN64) && !defined(_LIBCXXABI_ARM_EHABI)
    // This is a new field to support C++ 0x exception_ptr.
    // For binary compatibility it is placed where the compiler
    // previously adding padded to 64-bit align unwindHeader.
    size_t referenceCount;
#endif
    _Unwind_Exception unwindHeader;
};


namespace base {
namespace mac {

extern "C" _Unwind_Reason_Code __gxx_personality_v0(int,
                                                    _Unwind_Action,
                                                    uint64_t,
                                                    struct _Unwind_Exception*,
                                                    struct _Unwind_Context*);

_Unwind_Reason_Code CxxPersonalityRoutine(
                                          int version,
                                          _Unwind_Action actions,
                                          uint64_t exception_class,
                                          struct _Unwind_Exception* exception_object,
                                          struct _Unwind_Context* context) {
  // Unwinding is a two-phase process: phase one searches for an exception
  // handler, and phase two performs cleanup. For phase one, this custom
  // personality will terminate the search. For phase two, this should delegate
  // back to the standard personality routine.
  __cxa_exception* exception_header =
      (__cxa_exception*)(exception_object + 1) - 1;
  std::cout << __FUNCTION__ << ": " << actions << " " << exception_header->exceptionType->name() << "\n";
  
  if ((actions & _UA_SEARCH_PHASE) != 0) {
    // Tell libunwind that this is the end of the stack. When it encounters the
    // CallWithEHFrame, it will stop searching for an exception handler. The
    // result is that no exception handler has been found higher on the stack,
    // and any that are lower on the stack (e.g. in CFRunLoopRunSpecific), will
    // now be skipped. Since this is reporting the end of the stack, and no
    // exception handler will have been found, std::terminate() will be called.
    
    // invalid try catch outside CALL_WITH_EH_FRAME block
    //  CALL_WITH_EH_FRAME(^{
    //      @throw [NSException exceptionWithName:@"1" reason:nil userInfo:nil];
    //  });
    
    return _URC_END_OF_STACK;
  }
  
  
  return __gxx_personality_v0(version, actions, exception_class,
                              exception_object, context);
}
}
}
