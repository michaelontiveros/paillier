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
  printf("\n\n");

  mpz_t q;
  mpz_init(q);
  mpz_urandomb(q, state, keysize);
  mpz_nextprime(q, q);

  printf("prime q\n");
  mpz_out_str(stdout, 16, q);
  printf("\n\n");

  mpz_mul(pk,  p,  q);
  mpz_mul(pk2, pk, pk);

  printf("public key\n");
  mpz_out_str(stdout, 16, pk);
  printf("\n\n");

  mpz_sub_ui(p, p, 1);
  mpz_sub_ui(q, q, 1);
  mpz_mul(  sk, p, q);

  printf("secret key\n");
  mpz_out_str(stdout, 16, sk);
  printf("\n\n");

  mpz_invert(ski, sk, pk);

  mpz_clear(p);
  mpz_clear(q);
}

void Paillier::writes() {
  uint16_t k;
  
  for(k = 0; k < 255; k++) {
    str[k] = 0;
  }
  
  printf("write a message and press enter\n");
  uint8_t character = getchar();
  k = 0;
  while(k < 255 && character != '\n') {
    str[k] = character;
    character = getchar();
    k++;
  }
  printf("\n");
}

void Paillier::encrypts() {
  if(mpz_cmp_ui(pk, 0) == 0) {
    printf("missing public key\n\n");
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

  printf("plaintext\n");
  printstr();
  mpz_out_str(stdout, 16, pt);
  printf("\n\n");

  printf("random number\n");
  mpz_out_str(stdout, 16, random);
  printf("\n\n");

  mpz_add_ui(pk, pk, 1);
  mpz_powm(ct, pk, pt, pk2);
  mpz_sub_ui(pk, pk, 1);
  mpz_powm(random, random, pk, pk2);
  mpz_mul(ct, ct, random);
  mpz_mod(ct, ct, pk2);

  printf("ciphertext\n");
  mpz_out_str(stdout, 16, ct);
  printf("\n\n");

  mpz_clear(random);
  mpz_clear(gcd);
}

void Paillier::decrypts() {
  if(mpz_cmp_ui(sk, 0) == 0) {
    printf("missing secret key\n\n");
    return;
  }

  mpz_powm(pt, ct, sk, pk2);
  mpz_sub_ui(pt, pt, 1);
  mpz_div(   pt, pt, pk);
  mpz_mul(   pt, pt, ski);
  mpz_mod(   pt, pt, pk);

  num2str(pt, str);

  printf("decryption\n");
  printstr();
  mpz_out_str(stdout, 16, pt);
  printf("\n\n");
}

void Paillier::printstr() {
  uint16_t k;

  for(k = 0; k < 255; k++) {
    printf("%c", str[k]);
  }
  printf("\n");
}

void Paillier::clear() {
  gmp_randclear(state);
  mpz_clear(pk);
  mpz_clear(pk2);
  mpz_clear(sk);
  mpz_clear(ski);
  mpz_clear(pt);
  mpz_clear(ct);
}

void str2num(uint8_t *str, mpz_t &num) {
  uint16_t k;
  mpz_set_ui(num, 0);
  for(k = 0; k < 255; k++) {
    mpz_mul_ui(num, num, 256);
    mpz_add_ui(num, num, str[k]);
  }
}

void num2str(mpz_t &num, uint8_t *str) {
  uint16_t k;
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
