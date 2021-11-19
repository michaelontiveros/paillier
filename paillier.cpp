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

  for(uint16_t k = 0; k < 256; k++) {
    msg[k] = 0;
  }
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
  
  mpz_t q;
  mpz_init(q);
  mpz_urandomb(q, state, keysize);
  mpz_nextprime(q, q);
  
  mpz_mul(pk,  p,  q);
  mpz_mul(pk2, pk, pk);
  
  mpz_sub_ui(p, p, 1);
  mpz_sub_ui(q, q, 1);
  mpz_mul(  sk, p, q);
  
  mpz_invert(ski, sk, pk);

  printkeys(p, q);
  mpz_clear(p);
  mpz_clear(q);
}

void Paillier::printkeys(mpz_t &p, mpz_t &q) {
  printf("\ngenerated...");
  printf(     "\n\nprime p\n");
  mpz_out_str(stdout, 16, p);
  
  printf(   "\n\nprime q\n");
  mpz_out_str(stdout, 16, q);
  
  printf("\n\npublic key\n");
  mpz_out_str(stdout, 16, pk);
  
  printf("\n\nsecret key\n");
  mpz_out_str(stdout, 16, sk);
}

void Paillier::sendskey(Paillier &alice) {
  mpz_set(   alice.pk,  pk);
  mpz_set(   alice.pk2, pk2);
  mpz_set_ui(alice.sk,  0);
  mpz_set_ui(alice.ski, 0);
}

void Paillier::writes() {
  printf("\nwrite a message, then press enter\n");
  
  uint16_t k = 0;
  uint8_t character = getchar();
  
  while(character == '\n') {
    character = getchar();
  }
  
  while(k < 256 && character != '\n') {
    msg[k] = character;
    character = getchar();
    k++;
  }
  while(k < 256) {
    msg[k] = 0;
    k++;
  }

  msg2pt(msg, pt, pk);
}

void Paillier::encrypts() {
  if(mpz_cmp_ui(pk, 0) == 0) {
    printf("\nmissing public key\n\n");
    return;
  }

  mpz_t r;
  mpz_init(r);
  mpz_urandomm(r, state, pk);

  mpz_t gcd;
  mpz_init(gcd);
  mpz_gcd(gcd, r, pk);
  while(mpz_cmp_ui(gcd, 1) != 0) {
    printf("gcd(r, n) != 1\n");
    mpz_urandomm(r, state, pk);
    mpz_gcd(gcd, r, pk);
  }
  
  mpz_add_ui(pk, pk, 1);
  mpz_powm(ct, pk, pt, pk2);
  mpz_sub_ui(pk, pk, 1);
  mpz_powm(r, r, pk, pk2);
  mpz_mul(ct, ct, r);
  mpz_mod(ct, ct, pk2);
  
  mpz_clear(r);
  mpz_clear(gcd);
}

void Paillier::printenc() {
  printf("\nplaintext\n");
  printmsg();
  mpz_out_str(stdout, 16, pt);
  
  printf("\n\nciphertext\n");
  mpz_out_str(stdout, 16, ct);
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

  pt2msg(pt, msg);
}

void Paillier::printdec() {
  printf("\ndecryption\n");
  printmsg();
  mpz_out_str(stdout, 16, pt);
  printf("\n\n");
}

void Paillier::printmsg() {
  for(uint16_t k = 0; k < 256; k++) {
    printf("%c", msg[k]);
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

void ot(Paillier &alice, Paillier &bob) {
  mpz_t pt0, pt1, ct0, ct1, r0, r1;
  mpz_init(pt0);
  mpz_init(pt1);
  mpz_init(ct0);
  mpz_init(ct1);
  mpz_init( r0);
  mpz_init( r1);

  printf("\n\n-------");
  printf(  "\n| bob |");
  printf(  "\n-------");
  bob.genkeys();
  bob.sendskey(alice);

  printf("\n\ntype 0 (or 1) to read alice's 0th (or 1st) message,");
  printf(" then press enter\n");
  mpz_set_ui(bob.pt, getchar() % 2);
  bob.encrypts();
  bob.printenc();

  mpz_urandomm(r0, alice.state, alice.pk);
  mpz_urandomm(r1, alice.state, alice.pk);
  
  mpz_set_ui(alice.pt, 0);
  alice.encrypts();
  mpz_set(ct0, alice.ct);
  mpz_mul(ct0, ct0, bob.ct);
  mpz_mod(ct0, ct0, alice.pk2);
  mpz_powm(ct0, ct0, r0, alice.pk2);

  mpz_sub_ui(alice.pk, alice.pk, 1);
  mpz_set(alice.pt, alice.pk);
  mpz_add_ui(alice.pk, alice.pk, 1);
  alice.encrypts();
  mpz_set(ct1, alice.ct);
  mpz_mul(ct1, ct1, bob.ct);
  mpz_mod(ct1, ct1, alice.pk2);
  mpz_powm(ct1, ct1, r1, alice.pk2);

  printf("\n\n---------");
  printf(  "\n| alice |");
  printf(  "\n---------");
  alice.writes();
  alice.encrypts();
  mpz_mul(ct0, ct0, alice.ct);
  mpz_mod(ct0, ct0, alice.pk2);
  alice.writes();
  alice.encrypts();
  mpz_mul(ct1, ct1, alice.ct);
  mpz_mod(ct1, ct1, alice.pk2);
 
  printf(  "\n-------");
  printf(  "\n| bob |");
  printf(  "\n-------");
  mpz_set(bob.ct, ct0);
  bob.decrypts();
  bob.printdec();

  mpz_set(bob.ct, ct1);
  bob.decrypts();
  bob.printdec();

  alice.clears();
  bob.clears();

  mpz_clear(pt0);
  mpz_clear(pt1);
  mpz_clear(ct0);
  mpz_clear(ct1);
  mpz_clear( r0);
  mpz_clear( r1);
}

void msg2pt(uint8_t *msg, mpz_t &pt, mpz_t &pk) {
  mpz_t ptcopy;
  mpz_init_set_ui(ptcopy, 0);
  
  for(uint16_t k = 0; k < 256; k++) {
    if(mpz_cmp(ptcopy, pk) < 0) {
      mpz_set(pt, ptcopy);
      mpz_mul_ui(ptcopy, ptcopy, 256);
      mpz_add_ui(ptcopy, ptcopy, msg[k]);
    }
  }

  if(mpz_cmp(ptcopy, pk) < 0) {
    mpz_set(pt, ptcopy);
  }

  mpz_clear(ptcopy);
}

void pt2msg(mpz_t &pt, uint8_t *msg) {
  mpz_t byte, character, ptcopy;;
  mpz_init_set_ui(byte, 256);
  mpz_init(character);
  mpz_init_set(ptcopy, pt);
  
  for(uint16_t k = 0; k < 256; k++) {
    mpz_mod(character, ptcopy, byte);
    msg[255 - k] = mpz_get_ui(character);
    mpz_sub(   ptcopy, ptcopy, character);
    mpz_cdiv_q(ptcopy, ptcopy, byte);
  }
  
  mpz_clear(byte);
  mpz_clear(character);
  mpz_clear(ptcopy);
}
