#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>


//用于支持配置文件中的动态字符串 如 "wget {URL} -o down.zip"
std::string string_replace(std::string source, std::string find, std::string replace);
//用于支持配置文件中的字符串转数字
template <class T>
void convertFromString(T& value, const std::string& s) {
	std::stringstream ss(s);
	ss.precision(s.length());
	ss >> value;
}
//用于安全读取配置文件（只用config.find(key)->second写错了key会导致报错）
std::string read_config(std::map<std::string, std::string> config, std::string key);

//解析配置文件，并添加默认配置
std::map<std::string, std::string> get_configs(std::string fname);
