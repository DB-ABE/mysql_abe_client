#include "SQLParser.h"
#include "util/sqlhelper.h"
#include <string>
#include <iostream>
#include <vector>

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

    //需要解密的列名
    std::vector<string> field_name_list() const {
        std::vector<string> list;
        list.push_back(dec_plan.field_name);       //当前只有一个dec_plan，后续可考虑支持多个
        return list;
    }


private:
    bool is_select; //true:查询，包括select/show，需要输出查询结果，false:其它语句
    bool is_enc;    //true:加密时，一般为插入 
    bool is_dec;    //true,解密一般为查询

    string raw_sql; //用户输入sql

    struct enc_field enc_plan;  //一个改写点    当前只考虑一个改写点，即只有一个abe_enc()

    string real_sql;

    //解密需要：
    struct dec_field dec_plan;
    

};