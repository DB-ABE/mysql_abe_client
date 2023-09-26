#include "my_utils/cxxopts.hpp"
#include "SQLParser.h"
#include "util/sqlhelper.h"
#include <mysql++.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <csignal>
#include <vector>

#include "rewrite.h"

using std::string;

//解析命令行参数
cxxopts::ParseResult parse_opt(int argc, char *argv[]){
    cxxopts::Options options("abe_client", "A demo of abe client for mysql");

    options.add_options()
        ("u,username", "username of database server", cxxopts::value<string>())
        ("p,password", "password of the user", cxxopts::value<string>())
        ("h,host", "the hostname of the database server", cxxopts::value<string>()->default_value("127.0.0.1"))
        ("P,port", "the port of the database server", cxxopts::value<unsigned int>()->default_value("3306"))
        ("D,database", "the database you want to connect", cxxopts::value<string>()->default_value("mysql"))
        ("help", "print this usage info")
    ;

    auto result = options.parse(argc, argv);

    if (result.count("help"))
    {
      std::cout << options.help() << std::endl;
      exit(0);
    }

    if(result.count("username") == 0 || result.count("password") == 0){
        std::cerr << "error: both -u/--username and -p/--password are required." << std::endl;
        std::cout << options.help() << std::endl;
        exit(0);
    }
    return result;
}

//捕获ctrl+c
void handle_signal(int signal) {
    if (signal == SIGINT ) {
        // 用户输入ctrl+c，清空当前输入缓冲区并显示下一个命令提示符
        std::cout << "\nabe_client> ";
        std::cout.flush();
    }
}

int main(int argc, char *argv[])
{
    std::signal(SIGINT, handle_signal);

    auto opts = parse_opt(argc, argv);

    string username, password, host, database;
    unsigned int port;
    username = opts["username"].as<string>();
    password = opts["password"].as<string>();
    host = opts["host"].as<string>();
    port = opts["port"].as<unsigned int>();
    database = opts["database"].as<string>();

    std::string input;
    mysqlpp::Connection conn(false);
    if (!conn.connect(database.c_str(), host.c_str(), username.c_str(), password.c_str(), port)){
        std::cerr << "DB connection failed: " << conn.error() << std::endl;
        return 1;
    }
    while (true) {
        std::cout << "abe_client> ";
        if (!std::getline(std::cin, input) || input == "exit") {
            // 用户输入ctrl+d (EOF)或exit，退出客户端
            std::cout << "\nBye!" << std::endl;
            break;
        }

        //1. 解析sql语句并根据需要重写
        std::string real_sql;
        rewrite_plan my_rewrite_plan(input);
        my_rewrite_plan.parse_and_rewrite(real_sql);

        //2. 执行sql语句得到结果
        //todo: a-解密，b-获取abe密钥后解密保存在指定目录中
       
        std::cout << "处理命令: " << real_sql << std::endl;
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
                        //注意mysql++的row[j]并非是std::string，而是其自己实现的String类，需做一定的转换
                        // string plaintext = row[j];  
                        std::cout << res.field_name(j) << "(decrypted):\t" << row[j] << std::endl;
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