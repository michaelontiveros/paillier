#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include "paillier.h"

// compile  with the command
// c++ main.cpp paillier.cpp -o main -lgmp

// then run with the command
// ./main

int main() {
  printf("\n\"2 choose 1\" oblivious transfer");
  printf("\nfrom the paillier encryption scheme");
  
  Paillier alice, bob;
  
  ot(alice, bob);

  return 0;
}
