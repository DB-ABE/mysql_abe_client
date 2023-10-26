#ifndef ABE_CRYPTO_H
#define ABE_CRYPTO_H
#include <string.h>
#include <fstream>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>

using namespace oabe;
using namespace oabe::crypto;
using std::string;


#define RSA_Encrypt_length 245
#define RSA_Decrypt_length 256

struct abe_user{
  string user_id;
  string user_key = "";
  string user_attr;
};

class abe_crypto{
public:

    abe_crypto(string name){user.user_id = name;}//name或者说user_id，即用户标识，一般和登录的数据库用户同名

    bool init(string mpk_path, string key_path, string kms_cert_path, string db_cert_path);
    void set_name(string namehost){user.user_id = namehost;}
    bool import_mpk(string mpk_path);
    bool import_user_key(string key_path);
    bool save_user_key(string key_path, string key_str);
    bool check_abe_key();   //true: abe_key已存在

    bool encrypt(string pt, string policy, string &ct);
    bool decrypt(string ct, string &pt);

    bool import_db_cert(string db_cert_path);
    bool import_kms_cert(string kms_cert_path);
    bool import_sk(string rsa_sk_path);
    
    bool verify_db_sig(const string msg, const string sig_db);
    bool verify_kms_sig(const string msg, const string sig_kms);

    struct abe_user user;
    ~abe_crypto();
private:
    string mpk;
    RSA *kms_pk = NULL;
    RSA *db_pk = NULL;
    RSA *sk = NULL;
    bool verify_sig(const string msg, const string sig_db, RSA *pk);
    bool rsa_decrypt(const string ct, string &pt);
};
#endif