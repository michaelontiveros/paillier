#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include "paillier.h"

Paillier::Paillier() {
  setstate();
  keysize = 1024;
  mpz_init_set_ui(pk , 0);
  mpz_init_set_ui(pk2, 0);
  mpz_init_set_ui(sk , 0);
  mpz_init_set_ui(ski, 0);
  mpz_init_set_ui(pt , 0);
  mpz_init_set_ui(ct , 0);

  printf("\nthe paillier encryption scheme\n");
}

void Paillier::setstate() {
  gmp_randinit_mt(state);
  gmp_randseed_ui(state, clock());
}

void Paillier::genkeys() {
  mpz_t p;
  mpz_init(p);
  mpz_urandomb( p, state, keysize);
  mpz_nextprime(p, p);
  
  printf("\nprime p\n");
  mpz_out_str(stdout, 16, p);

  mpz_t q;
  mpz_init(q);
  mpz_urandomb(q, state, keysize);
  mpz_nextprime(q, q);

  printf("\n\nprime q\n");
  mpz_out_str(stdout, 16, q);

  mpz_mul(pk,  p,  q);
  mpz_mul(pk2, pk, pk);

  printf("\n\npublic key\n");
  mpz_out_str(stdout, 16, pk);

  mpz_sub_ui(p, p, 1);
  mpz_sub_ui(q, q, 1);
  mpz_mul(  sk, p, q);

  printf("\n\nsecret key\n");
  mpz_out_str(stdout, 16, sk);

  mpz_invert(ski, sk, pk);

  mpz_clear(p);
  mpz_clear(q);
}

void Paillier::writes() {
  printf("\n\nwrite a message and press enter\n");
  uint8_t k = 0;
  uint8_t character = getchar();
  while(k < 255 && character != '\n') {
    str[k] = character;
    character = getchar();
    k++;
  }
  while(k < 255) {
    str[k] = 0;
    k++;
  }
}

void Paillier::encrypts() {
  if(mpz_cmp_ui(pk, 0) == 0) {
    printf("\nmissing public key\n\n");
    return;
  }

  str2num(str, pt);

  mpz_t random;
  mpz_init(random);
  mpz_urandomm(random, state, pk);

  mpz_t gcd;
  mpz_init(gcd);
  mpz_gcd(gcd, random, pk);
  while(mpz_cmp_ui(gcd, 1) != 0) {
    printf("gcd(r, n) != 1\n");
    mpz_urandomm(random, state, pk);
    mpz_gcd(gcd, random, pk);
  }

  printf("\nplaintext\n");
  printstr();
  mpz_out_str(stdout, 16, pt);
  printf("\n\nrandom number\n");
  mpz_out_str(stdout, 16, random);

  mpz_add_ui(pk, pk, 1);
  mpz_powm(ct, pk, pt, pk2);
  mpz_sub_ui(pk, pk, 1);
  mpz_powm(random, random, pk, pk2);
  mpz_mul(ct, ct, random);
  mpz_mod(ct, ct, pk2);

  printf("\n\nciphertext\n");
  mpz_out_str(stdout, 16, ct);

  mpz_clear(random);
  mpz_clear(gcd);
}

void Paillier::decrypts() {
  if(mpz_cmp_ui(sk, 0) == 0) {
    printf("\n\nmissing secret key\n\n");
    return;
  }

  mpz_powm(pt, ct, sk, pk2);
  mpz_sub_ui(pt, pt, 1);
  mpz_div(   pt, pt, pk);
  mpz_mul(   pt, pt, ski);
  mpz_mod(   pt, pt, pk);

  num2str(pt, str);

  printf("\n\ndecryption\n");
  printstr();
  mpz_out_str(stdout, 16, pt);
  printf("\n\n");
}

void Paillier::printstr() {
  uint8_t k;

  for(k = 0; k < 255; k++) {
    printf("%c", str[k]);
  }
  printf("\n");
}

void Paillier::clears() {
  gmp_randclear(state);
  mpz_clear(pk);
  mpz_clear(pk2);
  mpz_clear(sk);
  mpz_clear(ski);
  mpz_clear(pt);
  mpz_clear(ct);
}

void str2num(uint8_t *str, mpz_t &num) {
  uint8_t k;
  
  mpz_set_ui(num, 0);
  for(k = 0; k < 255; k++) {
    mpz_mul_ui(num, num, 256);
    mpz_add_ui(num, num, str[k]);
  }
}

void num2str(mpz_t &num, uint8_t *str) {
  uint8_t k;
  
  mpz_t byte;
  mpz_init_set_ui(byte, 256);
  mpz_t character;
  mpz_init(character);
  mpz_t numcopy;
  mpz_init_set(numcopy, num);
  for(k = 0; k < 255; k++) {
    mpz_mod(character, numcopy, byte);
    str[254 - k] = mpz_get_ui(character);
    mpz_sub(   numcopy, numcopy, character);
    mpz_cdiv_q(numcopy, numcopy, byte);
  }
  mpz_clear(byte);
  mpz_clear(character);
  mpz_clear(numcopy);
}
