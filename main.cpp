// #include "my_utils/cxxopts.hpp"
// #include "my_utils/config.hpp"
// #include "SQLParser.h"
// #include "util/sqlhelper.h"
#include <mysql++.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <csignal>
#include <vector>
#include <map>


#include <iostream>
#include <string>
#include <cassert>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>

using namespace oabe;
using namespace oabe::crypto;


#include "rewrite.h"
#include "abe_crypto.h"
#include "parameters.h"

using std::string;


//捕获ctrl+c
void handle_signal(int signal) {
    if (signal == SIGINT ) {
        // 用户输入ctrl+c，清空当前输入缓冲区并显示下一个命令提示符
        std::cout << "\nabe_client> ";
        std::cout.flush();
    }
}


// std::map<std::string, std::string> config = get_configs("config.txt");
int main(int argc, char *argv[])
{
    std::signal(SIGINT, handle_signal);

    struct parameters params;
    read_config_file(params);
    read_opt(params, argc, argv);
    
    abe_crypto my_abe("user1");//暂时使用user1，之后需要通过select current_user()获取
    if(!my_abe.init(params.abe_pp_path, params.abe_key_path)){
        return 0;
    }

    std::string input;
    mysqlpp::Connection conn(false);
    if (!conn.connect(params.database.c_str(), params.host.c_str(), params.username.c_str(),
         params.password.c_str(), params.port)){
        std::cerr << "DB connection failed: " << conn.error() << std::endl;
        return 0;   
    }
    while (true) {
        std::cout << "abe_client> ";
        if (!std::getline(std::cin, input) || input == "exit" || input == "q") {
            // 用户输入ctrl+d (EOF)或exit，退出客户端
            std::cout << "\nBye!" << std::endl;
            break;
        }

        //1. 解析sql语句并根据需要重写
        std::string real_sql;
        rewrite_plan my_rewrite_plan(input);
        my_rewrite_plan.set_crypto(my_abe);
        my_rewrite_plan.parse_and_rewrite(real_sql);

        //2. 执行sql语句得到结果
        //todo: a-解密，b-获取abe密钥后解密保存在指定目录中
       
        mysqlpp::Query query = conn.query(real_sql.c_str());
        if (mysqlpp::StoreQueryResult res = query.store()) {
            int field_num = res.num_fields();
            int row_num = res.num_rows();
            if (row_num == 0){
                std::cout << "empty set" << std::endl;
                continue;
            }
            
            std::cout << row_num << " rows in set" << std::endl;
            mysqlpp::StoreQueryResult::const_iterator it;
            int i = 0;
            for (it = res.begin(); it != res.end(); ++it) {
                mysqlpp::Row row = *it;
                std::cout << "[record " << i << "]------------------" << std::endl;

                std::vector<string> field_name_list = my_rewrite_plan.field_name_list();

                for (int j = 0; j < field_num ; j++){
                    //如果my_rewrite_plan中有需要解密的字段，则先解密再输出
                    
                    if(my_rewrite_plan.need_dec() && std::find(field_name_list.begin(), field_name_list.end(), 
                        res.field_name(j))  != field_name_list.end()){
                        //在要解密的列表中，需解密输出
                        //mysql++的row[j]并非是std::string，而是其自己实现的String类，需做一定的转换
                        string ct(row[j].c_str());  
                        string pt;
                        my_rewrite_plan.crypto->decrypt(ct,pt);
                        std::cout << res.field_name(j) << "(decrypted):\t" << pt << std::endl;
                    }else{
                        std::cout << res.field_name(j) << ":\t" << row[j] << std::endl;
                    }

                }
                i++;
            }
        }
        else if (query.errnum() == 0 && res.empty()){
            int affected_row_num = query.affected_rows();
            std::cout << "Query OK, " << affected_row_num << " rows affected" << std::endl;
        }
        else{
            std::cerr << "Query failed: " << query.error() << std::endl;
            continue;
        }

    }
    return 0;
}