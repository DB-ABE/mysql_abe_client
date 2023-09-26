#include "rewrite.h"
#include <regex>
#include <iostream>
#include <string>
#include <algorithm>
using std::string;


/*因sql-parser库对mysql语句支持很不友好，且当前并未找到实用的sql解析库
*（最好是能解析mysql语句，然后可以反序列化，即解析后修改相关项，恢复成sql语句）
* 暂使用正则表达式实现abe_enc/abe_dec的匹配和重写
*/
const string ABE_ENC_SQL_REGEX = ".*abe_enc\\(\\s*['\"`](\\w+)['\"`]\\s*,\\s*['\"`](\\w+)['\"`]\\s*\\).*";
const string ABE_ENC_REGEX = "abe_enc\\(\\s*['\"`](\\w+)['\"`]\\s*,\\s*['\"`](\\w+)['\"`]\\s*\\)";
const string ABE_DEC_SQL_REGEX = ".*abe_dec\\(\\s*[`]*(\\w+)[`]*\\s*\\).*";
const string ABE_DEC_REGEX = "abe_dec\\(\\s*[`]*(\\w+)[`]*\\s*\\)";


bool rewrite_plan::parse_and_rewrite(string &real_sql){
    
    std::string sql = raw_sql;
    //只有show/select命令需要打印查询结果，其他的不需要
    size_t spacePos = sql.find(' ');
    string firstWord = sql.substr(0, spacePos);
    transform(firstWord.begin(),firstWord.end(),firstWord.begin(),[](unsigned char c) { return std::tolower(c); });
    // string temp = firstWord.

    if(firstWord == "insert"){
        is_select = false;
        std::cout << "insert statement" << std::endl;
        std::regex pattern = std::regex(ABE_ENC_SQL_REGEX);
        std::smatch result;
        bool isMatch = std::regex_match(sql, result, pattern);
        if (isMatch) {
            is_enc = true;//需要加密
            //abe_enc只有两个参数，data和policy
            enc_plan.data = result[1];
            enc_plan.policy = result[2];
            // std::cout << enc_plan.data << std::endl;
            // std::cout << enc_plan.policy << std::endl;

            /*
            * todo: 此处调用加密组件进行加密，加密结果写入enc_plan.enc_data
            */
            
            enc_plan.enc_data = "'";
            enc_plan.enc_data = enc_plan.enc_data + "encrypted data";
            enc_plan.enc_data = enc_plan.enc_data + "'";
            
            std::regex pattern_enc = std::regex(ABE_ENC_REGEX);
            real_sql = std::regex_replace(sql, pattern_enc, enc_plan.enc_data);
	        std::cout << "after replace: " << real_sql << std::endl;
        }
        return true;
        
    }else if (firstWord == "select"){
        is_select = true;
        std::cout << "select statement" << std::endl;
         std::regex pattern = std::regex(ABE_DEC_SQL_REGEX);
        std::smatch result;
        bool isMatch = std::regex_match(sql, result, pattern);
        if (isMatch) {
            is_dec = true;//需要解密

            //abe_dec只有一个参数，field_name
            dec_plan.field_name = result[1];
            std::regex pattern_dec = std::regex(ABE_DEC_REGEX);
            real_sql = std::regex_replace(sql, pattern_dec, dec_plan.field_name);
	        std::cout << "after replace: " << real_sql << std::endl;
        }
        return true;

    }else{
        std::cout << "other statement" << std::endl;
        real_sql = sql;
        return true;
    }

    return true;
}