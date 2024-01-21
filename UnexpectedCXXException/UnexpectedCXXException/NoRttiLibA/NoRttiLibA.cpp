//
//  NoRttiLibA.cpp
//  NoRttiLibA
//
//  Created by songruiwang on 2024/1/21.
//

#include <iostream>
#include "NoRttiLibA.hpp"

void NoRttiLibA::HelloWorld(void)
{
  try {
    throw std::exception();
  } catch (std::exception &e) {
  }
};
