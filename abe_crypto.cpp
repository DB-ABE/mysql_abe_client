#include <fstream>
#include <cassert>
#include <iostream>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include "abe_crypto.h"
#include "my_utils/base64.h"

bool abe_crypto::encrypt(string pt, string policy, string &ct){
  
  InitializeOpenABE();
  OpenABECryptoContext cpabe("CP-ABE");
  cpabe.importPublicParams(mpk);
  cpabe.encrypt(policy.c_str(), pt, ct);
  ShutdownOpenABE();
  
//   std::cout<<"encrypt succefully!"<<std::endl;
  return true;
}

bool abe_crypto::decrypt(string ct, string &pt){
  
  if(!check_abe_key()){
    return false;
  }

  InitializeOpenABE();
  OpenABECryptoContext cpabe("CP-ABE");
  cpabe.importPublicParams(mpk);
  cpabe.importUserKey(user.user_id.c_str(), user.user_key);
  cpabe.decrypt(user.user_id.c_str(), ct, pt);
//   std::cout << "Recovered message: " << pt << std::endl;
  ShutdownOpenABE();
  
  return true;
}

bool abe_crypto::check_abe_key(){
    if(user.user_key == ""){
        std::cout << "there is no abe_key, please run:\n\tshow current_abe_key;\nto get from database" << std::endl;
        return false;
    }
    return true;
}


bool abe_crypto::init(string mpk_path, string key_path, string kms_cert_path, string db_cert_path){
    if(!(import_mpk(mpk_path) && import_db_cert(db_cert_path) && import_kms_cert(kms_cert_path))){
        return false;
    }
    if(!import_user_key(key_path)){
        user.user_key = "";
    }
    return true;
}

bool abe_crypto::import_mpk(string mpk_path){
    //读入mpk
    std::ifstream ifs_mpk(mpk_path, std::ios::in);
    if(!ifs_mpk){
        std::cerr << "error opening security pameter (mpk) file.\nmpk_path=" << mpk_path <<std::endl;
        return false;
    }
    ifs_mpk>>mpk;
    ifs_mpk.close();
    return true;
}

bool abe_crypto::import_user_key(string key_path){
    //读入abe_user_key
    std::ifstream ifs_key(key_path, std::ios::in);
    if(!ifs_key){
        std::cout << "there is no abe_key, please run:\n\tshow current_abe_key;\nto get from database" << std::endl;
        return false;
    }
    ifs_key>>user.user_key;
    ifs_key.close();
    return true;
}

bool abe_crypto::save_user_key(string key_path, string key_str){
    string pt;
    if(!rsa_decrypt(key_str, pt))
        return false;
    //写入abe_user_key
    std::ofstream ofs_key(key_path, std::ios::out);
    if(!ofs_key){
        std::cerr<<"error opening user key-file.\nkey_path=" << key_path <<std::endl;
        return false;
    }
    ofs_key << pt;
    user.user_key = pt;
    ofs_key.close();
    return true;
}

bool abe_crypto::import_sk(string rsa_sk_path){
    // 导入rsa密钥文件并读取密钥
    FILE *hPriKeyFile = fopen(rsa_sk_path.c_str(), "rb");
    if (hPriKeyFile == NULL)
    {
        // assert(false);
        return false;
    }
    std::string strRet;
    RSA *pRSAPriKey = RSA_new();
    if (PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
    { // 密钥读取失败
        // assert(false);
        RSA_free(pRSAPriKey);
        fclose(hPriKeyFile);
        return false;
    }
    sk = pRSAPriKey;
    fclose(hPriKeyFile);
    return true;
}
bool abe_crypto::import_db_cert(string db_cert_path){
    // 导入证书文件并读取公钥
    FILE *hPubKeyFile = fopen(db_cert_path.c_str(), "rb");
    if (hPubKeyFile == NULL)
    {
        // assert(false);
        return false;
    }
    X509 *cert = PEM_read_X509(hPubKeyFile, nullptr, nullptr, nullptr);
    EVP_PKEY *evp_key = X509_get_pubkey(cert);
    db_pk = EVP_PKEY_get1_RSA(evp_key);
    EVP_PKEY_free(evp_key);
    X509_free(cert);
    fclose(hPubKeyFile);
    return true;
}

bool abe_crypto::import_kms_cert(string kms_cert_path){
    // 导入证书文件并读取公钥
    FILE *hPubKeyFile = fopen(kms_cert_path.c_str(), "rb");
    if (hPubKeyFile == NULL)
    {
        // assert(false);
        return false;
    }
    X509 *cert = PEM_read_X509(hPubKeyFile, nullptr, nullptr, nullptr);
    EVP_PKEY *evp_key = X509_get_pubkey(cert);
    kms_pk = EVP_PKEY_get1_RSA(evp_key);
    EVP_PKEY_free(evp_key);
    X509_free(cert);
    fclose(hPubKeyFile);
    return true;
}

abe_crypto::~abe_crypto(){
    if(kms_pk!= NULL)   RSA_free(kms_pk);
    if(db_pk!= NULL)   RSA_free(db_pk);
    if(sk != NULL)  RSA_free(sk);
}

bool abe_crypto::verify_sig(const string msg_b64, const string sig_b64, RSA *pk){
    
    unsigned char digest[SHA512_DIGEST_LENGTH];

    //msg和sig都是base64编码，需要先解码
    size_t msg_b64_length = msg_b64.length();
    unsigned char * msg = (unsigned char*)malloc(base64_utils::b64_dec_len(msg_b64_length));
    size_t msg_length = base64_utils::b64_decode(msg_b64.c_str(), msg_b64_length, (char*)msg);

    size_t sig_b64_length = sig_b64.length();
    unsigned char * sig = (unsigned char*)malloc(base64_utils::b64_dec_len(sig_b64_length));
    size_t sig_length = base64_utils::b64_decode(sig_b64.c_str(), sig_b64_length, (char*)sig);

    // 对输入进行hash并转换16进制
    SHA512(msg, msg_length, digest);

    // 对签名进行认证
    int ret = RSA_verify(NID_sha512, digest, SHA512_DIGEST_LENGTH, sig, sig_length, pk);
    if (ret != 1){
        std::cout << "verify error\n";
        unsigned long ulErr = ERR_get_error();
        char szErrMsg[1024] = {0};
        std::cout << "error number:" << ulErr << std::endl;
        ERR_error_string(ulErr, szErrMsg); // 格式：error:errId:库:函数:原因
        std::cout << szErrMsg << std::endl;
        free(msg);
        free(sig);
        return false;
    }
    free(msg);
    free(sig);
    return true;
}

bool abe_crypto::verify_db_sig(const string msg, const string sig_db){
    if(!verify_sig(msg,sig_db,db_pk)){
        std::cout << "db_sig: verify failed\n";
        return false;
    }
    
    std::cout << "db_sig: verify success\n";
    return true;
}
bool abe_crypto::verify_kms_sig(const string msg, const string sig_kms){
    if(!verify_sig(msg,sig_kms,kms_pk)){
        std::cout << "kms_sig: verify failed\n";
        return false;
    }
    
    std::cout << "kms_sig: verify success\n";
    return true;
}

bool abe_crypto::rsa_decrypt(const string ct, string &pt){
    int nLen = RSA_size(sk);
    char *pDecode = new char[nLen + 1];
    bool flag = true;
    // 解密，不限长度，但为RSA_Decrypt_length的整数倍
    if (ct.length() < RSA_Decrypt_length + 1)
    { // 一个分组的情况
        int ret = RSA_private_decrypt(ct.length(), (const unsigned char *)ct.c_str(),
                                      (unsigned char *)pDecode, sk, RSA_PKCS1_PADDING);
        if (ret >= 0)
        { // 解密成功
            pt = std::string((char *)pDecode, ret);
        }
        else
        { // 解密失败
            pt = "";
            flag = false;
        }
    }
    else
    { // 多个分组
        for (int i = 0; i < (int)ct.length() / (int)RSA_Decrypt_length; i++)
        {
            std::string Data = ct.substr(i * RSA_Decrypt_length, RSA_Decrypt_length);
            int ret = RSA_private_decrypt(Data.length(), (const unsigned char *)Data.c_str(),
                                          (unsigned char *)pDecode, sk, RSA_PKCS1_PADDING);
            if (ret >= 0)
            {
                pt += std::string(pDecode, ret);
            }
            else
            { // 解密失败
                pt = "";
                flag = false;
                break;
            }
        }
        if (ct.length() % RSA_Decrypt_length != 0 && flag)
        {
            std::string Data = ct.substr((ct.length() / RSA_Decrypt_length) * RSA_Decrypt_length,
                                              ct.length() % ct.length());
            int ret = RSA_private_decrypt(Data.length(), (const unsigned char *)Data.c_str(),
                                          (unsigned char *)pDecode, sk, RSA_PKCS1_PADDING);
            if (ret >= 0)
            {
                pt += std::string(pDecode, ret);
            }
            else
            {
                pt = "";
                flag = false;
            }
        }
    }

    delete[] pDecode;
    CRYPTO_cleanup_all_ex_data();
    return flag;
}