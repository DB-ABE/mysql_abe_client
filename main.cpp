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

bool mysql_connect(mysqlpp::Connection &conn, const struct parameters &params){
    if (!conn.connect(params.database.c_str(), params.host.c_str(), params.username.c_str(),
         params.password.c_str(), params.port)){
        std::cerr << "DB connection failed: " << conn.error() << std::endl;
        return false;
    }
    return true;
}

void row_print(const rewrite_plan &my_rewrite_plan,  const mysqlpp::StoreQueryResult &res,
                const mysqlpp::Row &row, const int field_num){

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
}

bool save_abe_key(const rewrite_plan &my_rewrite_plan, const mysqlpp::StoreQueryResult &res,
                 const string &key_path){
    int field_num = res.num_fields();
    int row_num = res.num_rows();
    if(row_num != 1){
        std::cout << "It seems that you don't have the abe key, please contact the admininistrator" << std::endl;
    }
    if(field_num != my_rewrite_plan.TABLE_ABE_UER_KEY_FIELD_NUM){
        std::cout << "system table 'abe_user_key' error" << std::endl;
        return false;
    }

    mysqlpp::StoreQueryResult::const_iterator it = res.begin(); //只有一行
    mysqlpp::Row row = *it;
    std::cout << "[record " << 1 << "]------------------" << std::endl;
    std::cout << res.field_name(my_rewrite_plan.F_OWNER_NUM) << ":\t" 
                            << row[my_rewrite_plan.F_OWNER_NUM] << std::endl;
    std::cout << res.field_name(my_rewrite_plan.F_KEY_NUM) << ":\t" 
                            << row[my_rewrite_plan.F_KEY_NUM] << std::endl;
    std::cout << std::endl;

    string key_str(row[my_rewrite_plan.F_KEY_NUM].c_str());
    string sig_db(row[my_rewrite_plan.F_SIG_DB_NUM].c_str());
    string sig_db_type(row[my_rewrite_plan.F_SIG_DB_TYPE_NUM].c_str());
    string sig_kms(row[my_rewrite_plan.F_SIG_KMS_NUM].c_str());
    string sig_kms_type(row[my_rewrite_plan.F_SIG_KMS_TYPE_NUM].c_str());

    string namehost = my_rewrite_plan.crypto->user.user_id;
    string attrlist = my_rewrite_plan.crypto->user.user_attr;
    if(!(my_rewrite_plan.crypto->verify_db_sig(namehost + attrlist,sig_db) 
        && my_rewrite_plan.crypto->verify_kms_sig(key_str,sig_kms))){
            return false;
    }
    if(!my_rewrite_plan.crypto->save_user_key(key_path, key_str)){
        return false;
    }
    std::cout << "current abe user key saved successfully!" << std::endl;
    return true;
}

void mysql_query(mysqlpp::Connection &conn, rewrite_plan &my_rewrite_plan, const string &key_path){
    string query_sql = my_rewrite_plan.real_sql;
    mysqlpp::Query query = conn.query(query_sql.c_str());
    if (mysqlpp::StoreQueryResult res = query.store()) {
        
        //get abe key statment
        if(my_rewrite_plan.com_type == COM_GET_ABE_KEY){
            save_abe_key(my_rewrite_plan, res, key_path);
            return;
        }

        int field_num = res.num_fields();
        int row_num = res.num_rows();
        if (row_num == 0){
            std::cout << "empty set" << std::endl;
            return;
        }
        
        std::cout << row_num << " rows in set" << std::endl;
        mysqlpp::StoreQueryResult::const_iterator it;
        int i = 0;
        for (it = res.begin(); it != res.end(); ++it) {
            mysqlpp::Row row = *it;
            std::cout << "[record " << i << "]------------------" << std::endl;
            row_print(my_rewrite_plan, res, row, field_num);
            i++;
        }
    }
    else if (query.errnum() == 0 && res.empty()){
        int affected_row_num = query.affected_rows();
        std::cout << "Query OK, " << affected_row_num << " rows affected" << std::endl;
    }
    else{
        std::cerr << "Query failed: " << query.error() << std::endl;
    }
}

std::string get_current_user(mysqlpp::Connection conn){
    mysqlpp::Query query = conn.query("select current_user();");
    if (mysqlpp::StoreQueryResult res = query.store()) {
        
        int field_num = res.num_fields();
        int row_num = res.num_rows();
        if(row_num != 1 || field_num != 1)  return "";
        mysqlpp::StoreQueryResult::const_iterator it = res.begin(); //只有一行结果
        mysqlpp::Row row = *it;
        std::string namehost(row[0]);
        return namehost;
    }
    return "";
}

std::string get_current_user_abe_attribute(mysqlpp::Connection conn, string namehost){
    string sql = "select att from mysql.abe_attribute_manager where user = '" + namehost + "';";
    mysqlpp::Query query = conn.query(sql);
    if (mysqlpp::StoreQueryResult res = query.store()) {
        
        int field_num = res.num_fields();
        int row_num = res.num_rows();
        if(row_num != 1 || field_num != 1)  return "";
        mysqlpp::StoreQueryResult::const_iterator it = res.begin(); //只有一行结果
        mysqlpp::Row row = *it;
        std::string att(row[0]);
        return att;
    }
    return "";
}

// std::map<std::string, std::string> config = get_configs("config.txt");
int main(int argc, char *argv[])
{
    std::signal(SIGINT, handle_signal);

    struct parameters params;
    read_config_file(params);
    read_opt(params, argc, argv);
    
    abe_crypto my_abe("testabe@%");//暂时使用user1，之后需要通过select current_user()获取
    if(!my_abe.init(params.abe_pp_path, params.abe_key_path, 
                    params.kms_cert_path, params.db_cert_path,
                    params.rsa_sk_path)){
        return 0;
    }

    std::string input;
    mysqlpp::Connection conn(false);
    if(!mysql_connect(conn, params)){
        return 0;   
    }

    std::string namehost = get_current_user(conn);
    std::string attrlist;
    if(namehost == ""){
        std::cout << "can't get your username and host!" << std::endl;
    }else{
        my_abe.set_name(namehost);
        attrlist = get_current_user_abe_attribute(conn, namehost);
        if(attrlist == ""){
            std::cout << "can't get your attrlist, please contact adminastrator." << std::endl;
        }else{
            my_abe.set_att(attrlist);
        }
    }
    

    while (true) {
        std::cout << "abe_client> ";
        if (!std::getline(std::cin, input) || input == "exit" || input == "q") {
            // 用户输入ctrl+d (EOF)或exit，退出客户端
            std::cout << "\nBye!" << std::endl;
            break;
        }

        //1. 解析sql语句并根据需要重写
        rewrite_plan my_rewrite_plan(input);
        my_rewrite_plan.set_crypto(my_abe);
        my_rewrite_plan.parse_and_rewrite();

        //2. 执行sql语句得到结果
        mysql_query(conn,my_rewrite_plan, params.abe_key_path);

    }
    return 0;
}