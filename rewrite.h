// #include "SQLParser.h"
// #include "util/sqlhelper.h"
#ifndef REWRITE_H
#define REWRITE_H
#include <string>
#include <iostream>
#include <vector>
#include "abe_crypto.h"

using std::string;

//一个改写点，包括abe策略（用户输入）、明文data、密文enc_data
struct enc_field{
    string policy; 
    string data;
    string enc_data;
};

//解密改写点
struct dec_field{
    string field_name;  //要解密的field_name
    int field_num;   //要解密的field位置，如select a,b,abe_dec()的abe_dec位置为2（从0开始）
};


class rewrite_plan{
public:
    rewrite_plan(string input) :is_enc(false), is_dec(false), raw_sql(input) {}
    /*
    * input: 用户输入的原始sql语句
    * real_sql: 重写完成后真正要执行的sql语句
    */
    bool parse_and_rewrite(string &output);

    bool need_print() const{
        return is_select;
    }
    bool need_enc() const {
        return is_enc;
    }
    bool need_dec() const {
        return is_dec;
    }

    bool set_crypto(struct abe_crypto &c){
        crypto = &c;
        return true;
    }

    //需要解密的列名
    std::vector<string> field_name_list() const {
        std::vector<string> list;
        for(auto item : dec_plan){
            list.push_back(item.field_name);
        }
        return list;
    }

    struct abe_crypto * crypto; //abe算法

private:
    bool is_select; //true:查询，包括select/show，需要输出查询结果，false:其它语句
    bool is_enc;    //true:加密时，一般为插入 
    bool is_dec;    //true,解密一般为查询

    string raw_sql; //用户输入sql

    std::vector<struct enc_field> enc_plan;  //改写点列表

    string real_sql;

    //解密需要：
    std::vector<struct dec_field> dec_plan;

    

};
#endif