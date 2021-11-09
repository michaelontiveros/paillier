class Paillier {
public:
  mp_bitcnt_t        keysize;
  mpz_t              pk;      // public key p * q    
  mpz_t              pk2;     // pk^2
  uint8_t            str[255];
  mpz_t              pt;      // plaintext
  mpz_t              ct;      // ciphertext
  
  Paillier();
  //~Paillier(); 

  void genkeys();
  void writes();
  void encrypts();
  void decrypts();
  void clear();

private:
  gmp_randstate_t    state;
  mpz_t              sk;      // secret key (p - 1) * (q - 1) 
  mpz_t              ski;     // 1 / sk (mod pk)

  void setstate();
  void printstr();
};

void str2num(uint8_t *str, mpz_t   &num);
void num2str(mpz_t   &num, uint8_t *str);
