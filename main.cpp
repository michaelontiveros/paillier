#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include "paillier.h"

int main() {
  printf("\n\"2 choose 1\" oblivious transfer");
  printf("\nfrom the paillier encryption scheme");
  
  Paillier alice, bob;
  
  ot(alice, bob);

  return 0;
}
