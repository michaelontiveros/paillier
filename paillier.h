class Paillier {
public:
  mp_bitcnt_t        keysize; // 1024 bits per prime p, q
  mpz_t              pk;      // public key p * q    
  mpz_t              pk2;     // pk^2
  uint8_t            msg[256];// 256 = (2 * keysize) / 8
  mpz_t              pt;      // plaintext
  mpz_t              ct;      // ciphertext
  gmp_randstate_t    state;
  
  Paillier();
  //~Paillier(); 

  void genkeys();
  void encrypts();
  void decrypts();

  void sendskey(Paillier &alice);
  void writes();
  void clears();

  void printenc();
  void printdec();
  
private:
  mpz_t              sk;      // secret key (p - 1) * (q - 1) 
  mpz_t              ski;     // 1 / sk (mod pk)

  void setstate();
  
  void printkeys(mpz_t &p, mpz_t &q);
  void printmsg();
};

void ot(Paillier &alice, Paillier &bob);

void msg2pt(uint8_t *msg, mpz_t   &pt, mpz_t &pk);
void pt2msg(mpz_t   &pt,  uint8_t *msg);

