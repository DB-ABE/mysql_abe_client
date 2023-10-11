#ifndef PARAMETERS_H
#define PARAMETERS_H
#include "my_utils/config.h"
#include "my_utils/cxxopts.hpp"
#include <string>
using std::string;


struct parameters{
    string username;    //登录数据库的用户名
    string password;    //登录数据库的密码
    string host;        //登录数据库的IP
    unsigned int port;  //登录数据库的端口
    string database;    //数据库名

    string base_dir;    //基目录，完整路径为：基目录+配置文件中的目录

    string cacert_path; //CA证书路径
    string cert_path;   //自身的证书路径
    string rsa_sk_path; //rsa私钥路径

    string abe_key_path;    //abe密钥路径
    string abe_pp_path;     //abe公共参数路径，也可称mpk

    string abe_kms_ip;      //密钥管理中心IP
    unsigned int abe_kms_port;  //密钥管理中心端口
};

bool read_config_file(struct parameters &params);
bool read_opt(struct parameters &params, int argc, char *argv[]);

#endif