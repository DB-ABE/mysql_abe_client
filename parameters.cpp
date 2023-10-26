#include "parameters.h"
#include <string>
using std::string;

#define CONFIG_FILE "config.txt"
#define ERR_LOG_RET(x) std::cerr << (x) << std::endl;return false;


bool read_config_file(struct parameters &params){
    std::map<std::string, std::string> config = get_configs(CONFIG_FILE);

    std::string base_dir = read_config(config,"base_dir");
    if(base_dir == ""){
        base_dir = "./data/";
    }

    std::string temp;

/*以下参数可选提供*/
    std::string username = read_config(config,"username");
    if(username != ""){
        params.username = username;
    }

    std::string password = read_config(config,"password");
    if(password != ""){
        params.password =  password;
    }

    std::string host = read_config(config,"host");
    if(host != ""){
        params.host = host;
    }

    std::string port = read_config(config,"port");
    if(port != ""){
        convertFromString<unsigned int>(params.port, port);
    }

    std::string database = read_config(config,"database");
    if(database != ""){
        params.database = database;
    }
    

/*以下参数必须提供*/
//cacert
    std::string ca_cert_path = read_config(config,"ca_cert_path");
    if(ca_cert_path == ""){
        ERR_LOG_RET("read_config failed");
    }else{
        params.ca_cert_path = base_dir + ca_cert_path;
    }
//cert
    std::string cert_path = read_config(config,"cert_path");
    if(cert_path == ""){
        ERR_LOG_RET("read_config failed");
    }else{
        params.cert_path = base_dir + cert_path;
    }
//dbcert
    std::string db_cert_path = read_config(config,"db_cert_path");
    if(db_cert_path == ""){
        ERR_LOG_RET("read_config failed");
    }else{
        params.db_cert_path = base_dir + db_cert_path;
    }
//kmscert
    std::string kms_cert_path = read_config(config,"kms_cert_path");
    if(kms_cert_path == ""){
        ERR_LOG_RET("read_config failed");
    }else{
        params.kms_cert_path = base_dir + kms_cert_path;
    }
//rsa_sk
    std::string rsa_sk_path = read_config(config,"rsa_sk_path");
    if(rsa_sk_path == ""){
        ERR_LOG_RET("read_config failed");
    }else{
        params.rsa_sk_path = base_dir + rsa_sk_path;
    }


//abe_key
    std::string abe_key_path = read_config(config,"abe_key_path");
    if(abe_key_path == ""){
        ERR_LOG_RET("read_config failed");
    }else{
        params.abe_key_path = base_dir + abe_key_path;
    }
//abe_pp
    std::string abe_pp_path = read_config(config,"abe_pp_path");
    if(abe_pp_path == ""){
        ERR_LOG_RET("read_config failed");
    }else{
        params.abe_pp_path = base_dir + abe_pp_path;
    }

//abe_kms_ip
    std::string abe_kms_ip = read_config(config,"abe_kms_ip");
    if(abe_kms_ip == ""){
        ERR_LOG_RET("read_config failed");
    }else{
        params.abe_kms_ip = abe_kms_ip;
    } 
//abe_kms_port
    std::string abe_kms_port = read_config(config,"abe_kms_port");
    if(abe_kms_port == ""){
        ERR_LOG_RET("read_config failed");
    }else{
        convertFromString<unsigned int>(params.abe_kms_port, abe_kms_port);
    } 
    return true;
}

cxxopts::ParseResult parse_opt(int argc, char *argv[]);
bool read_opt(struct parameters &params, int argc, char *argv[]){
    auto opts = parse_opt(argc, argv);

    string username, password, host, database;
    unsigned int port;
    username = opts["username"].as<string>();
    password = opts["password"].as<string>();
    host = opts["host"].as<string>();
    port = opts["port"].as<unsigned int>();
    database = opts["database"].as<string>();

    params.username = username;
    params.password = password;
    params.host = host;
    params.port = port;
    params.database = database;


    //todo:下一步处理默认参数和从config中读取的参数之间的关系
    return true;

}

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

