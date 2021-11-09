#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include "paillier.h"

// compile using the following command
// c++ main.cpp paillier.cpp -o main -lgmp

int main() {
  Paillier alice;
  
  alice.genkeys();
  alice.writes();
  alice.encrypts();
  alice.decrypts();
  alice.clear();

  return 0;
}
