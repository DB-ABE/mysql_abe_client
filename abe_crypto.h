#ifndef ABE_CRYPTO_H
#define ABE_CRYPTO_H
#include <string.h>
#include <fstream>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>

using namespace oabe;
using namespace oabe::crypto;
using std::string;

struct abe_user{
  string user_id;
  string user_key;
  string user_attr;
};

class abe_crypto{
public:

    abe_crypto(string name){user.user_id = name;}//name或者说user_id，即用户标识，一般和登录的数据库用户同名

    bool init(string mpk_path, string key_path);
    bool import_mpk(string mpk_path);
    bool import_user_key(string key_path);

    bool encrypt(string pt, string policy, string &ct);
    bool decrypt(string ct, string &pt);
private:
    string mpk;
    struct abe_user user;
};
#endif