#include "rewrite.h"
#include <regex>
#include <iostream>
#include <string>
#include <algorithm>
using std::string;


/*因sql-parser库对mysql语句支持很不友好，且当前并未找到实用的sql解析库
*（最好是能解析mysql语句，然后可以反序列化，即解析后修改相关项，恢复成sql语句）
* 暂使用正则表达式实现abe_enc/abe_dec的匹配和重写
* 文本内容理论要求：不能为空
*　policy理论要求：\w(字母，数字，下划线)，| 属性分隔符，空白字符如空格等，等号，小数点，百分号
*/
const string ABE_ANY_R = ".*?";
const string ABE_COMMA_R = "\\s*,\\s*";
const string ABE_SUFIX_R = "\\s*\\)";

const string ABE_ENC_PREFIX_R = "abe_enc\\(\\s*";
const string ABE_ENC_DATA_R = "['\"`]((?:\\\\\"|\\\\\\(|\\\\\\)|[^\"\\(\\)])+)['\"`]"; // 真实正则：((?:\\"|\\\(|\\\)|[^\"\(\)])+)
const string ABE_ENC_POLICY_R = "['\"`]((?:\\\\\"|\\\\\\(|\\\\\\)|[^\"\\(\\)])+)['\"`]";
const string ABE_ENC_SQL_REGEX =  ABE_ANY_R + ABE_ENC_PREFIX_R + ABE_ENC_DATA_R
                                     + ABE_COMMA_R + ABE_ENC_POLICY_R + ABE_SUFIX_R + ABE_ANY_R;
const string ABE_ENC_REGEX = ABE_ENC_PREFIX_R + ABE_ENC_DATA_R
                                    + ABE_COMMA_R + ABE_ENC_POLICY_R + ABE_SUFIX_R;

const string ABE_DEC_PREFIX_R = "abe_dec\\(\\s*";
const string ABE_DEC_FIELD_R = "[`]*(\\w+)[`]*";
const string ABE_DEC_SQL_REGEX = ABE_ANY_R + ABE_DEC_PREFIX_R + ABE_DEC_FIELD_R + ABE_SUFIX_R + ABE_ANY_R;
const string ABE_DEC_REGEX = ABE_DEC_PREFIX_R + ABE_DEC_FIELD_R + ABE_SUFIX_R;
// const string ABE_ENC_SQL_REGEX = ".*abe_enc\\(\\s*['\"`](.+)['\"`]\\s*,\\s*['\"`](.+)['\"`]\\s*\\).*";
// const string ABE_ENC_REGEX = "abe_enc\\(\\s*['\"`](.+)['\"`]\\s*,\\s*['\"`](.+)['\"`]\\s*\\)";
// const string ABE_DEC_SQL_REGEX = ".*abe_dec\\(\\s*[`]*(\\w+)[`]*\\s*\\).*";
// const string ABE_DEC_REGEX = "abe_dec\\(\\s*[`]*(\\w+)[`]*\\s*\\)";


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
        std::regex pattern_enc = std::regex(ABE_ENC_REGEX);
        string new_sql = raw_sql;
        std::smatch result;
        while (std::regex_match(new_sql, result, pattern, std::regex_constants::format_first_only)){
            is_enc = true;//需要加密
            //abe_enc只有两个参数，data和policy
            struct enc_field temp;
            temp.data = result[1];
            temp.policy = result[2];
            // std::cout << enc_plan.data << std::endl;
            // std::cout << enc_plan.policy << std::endl;

            string cipher;
            crypto->encrypt(temp.data, temp.policy, cipher);
            
            temp.enc_data = "'";
            temp.enc_data = temp.enc_data + cipher;
            temp.enc_data = temp.enc_data + "'";
            
            new_sql = std::regex_replace(new_sql, pattern_enc, temp.enc_data, std::regex_constants::format_first_only);
            enc_plan.push_back(temp);
            std::cout << "new_sql: " << new_sql << std::endl;
        }

        real_sql = new_sql;
        std::cout << "after replace: " << real_sql << std::endl;
        return true;
        
    }else if (firstWord == "select"){
        is_select = true;
        std::cout << "select statement" << std::endl;
        std::regex pattern = std::regex(ABE_DEC_SQL_REGEX);
        std::regex pattern_dec = std::regex(ABE_DEC_REGEX);
        std::smatch result;
        string new_sql = raw_sql;
        while (std::regex_match(new_sql, result, pattern, std::regex_constants::format_first_only)){
            is_dec = true;//需要解密

            //abe_dec只有一个参数，field_name
            struct dec_field temp;
            temp.field_name = result[1];
            new_sql = std::regex_replace(new_sql, pattern_dec, temp.field_name, std::regex_constants::format_first_only);
            dec_plan.push_back(temp);
            std::cout << "new_sql: " << new_sql << std::endl;
        }
        real_sql = new_sql;
        std::cout << "after replace: " << real_sql << std::endl;
        return true;

    }else{
        std::cout << "other statement" << std::endl;
        real_sql = sql;
        return true;
    }

    return true;
}