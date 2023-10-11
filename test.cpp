
#include <stdlib.h>
#include <string>
#include <regex>
#include <iostream>
using std::string;
// include the sql parser
// #include "SQLParser.h"

// contains printing utilities
// #include "util/sqlhelper.h"

int main(int argc, char* argv[]) {
    string real_sql = "insert into company.kejibu values(\"1\",abe_enc(\"data\",\"policy\"))";
    string temp = "foo.txt";


    std::cout << "要处理的命令：" << real_sql << std::endl;

    string regex_expression = ".*abe_enc\\(['\"`](.*)['\"`],\\s*['\"`](.*)['\"`]\\).*";
    std::cout << "regex_expression: " << regex_expression << std::endl;

    std::regex pattern = std::regex(regex_expression);
    std::smatch result;
    bool isMatch = std::regex_match(real_sql, result, pattern);
    if (isMatch) {
        std::cout << "matched!" <<std::endl;
        std::cout << result[0].str() << std::endl;
        //abe_enc只有两个参数，data和policy
        // enc_plan.data = result[0];
        // enc_plan.policy = result[1];
        // std::cout << enc_plan.data << std::endl;
        // std::cout << enc_plan.policy << std::endl;
    }

}