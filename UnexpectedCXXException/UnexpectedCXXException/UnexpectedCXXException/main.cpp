//
//  main.cpp
//  UnexpectedCXXException
//
//  Created by songruiwang on 2024/1/21.
//

#include <iostream>
#include "NoRttiLibA.hpp"

int main(int argc, const char * argv[]) {
  try {
    throw std::logic_error("something bad");
  } catch (std::exception &e) {
    printf("%s\n", e.what());
  }
  
  return 0;
}
