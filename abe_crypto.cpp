#include <fstream>
#include <cassert>
#include <iostream>
#include <unistd.h>
#include "abe_crypto.h"

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
  
  InitializeOpenABE();
  OpenABECryptoContext cpabe("CP-ABE");
  cpabe.importPublicParams(mpk);
  cpabe.importUserKey(user.user_id.c_str(), user.user_key);
  cpabe.decrypt(user.user_id.c_str(), ct, pt);
//   std::cout << "Recovered message: " << pt << std::endl;
  ShutdownOpenABE();
  
  return 1;
}

bool abe_crypto::init(string mpk_path, string key_path){
    if(import_mpk(mpk_path) && import_user_key(key_path)){
        return true;
    }
    return false;
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
        std::cerr<<"error opening user key-file.\nkey_path=" << key_path <<std::endl;
        return false;
    }
    ifs_key>>user.user_key;
    ifs_key.close();
    return true;
}