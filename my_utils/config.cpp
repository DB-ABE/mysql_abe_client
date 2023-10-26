#include "config.h"

//-------------三个辅助函数-------------
//用于支持配置文件中的动态字符串 如 "wget {URL} -o down.zip"
std::string string_replace(std::string source, std::string find, std::string replace)
{
	std::string::size_type pos = 0;
	std::string::size_type a = find.size();
	std::string::size_type b = replace.size();
	while ((pos = source.find(find, pos)) != std::string::npos)
	{
		//source.replace(pos, a, replace);
		source.erase(pos, a);
		source.insert(pos, replace);
		pos += b;
	}
	return source;
}

//用于安全读取配置文件（只用config.find(key)->second写错了key会导致报错）
std::string read_config(std::map<std::string, std::string> config, std::string key) {
	auto it = config.find(key);
	if (it == config.end()) {
		return "";
	}
	else {
		return it->second;
	}
}
 
//-------------四个主要函数-------------
//用于去除字符串多余的空格
std::string trim(std::string text)
{
	if (!text.empty())
	{
		text.erase(0, text.find_first_not_of(" \n\r\t"));//去除字符串头部的空格
		text.erase(text.find_last_not_of(" \n\r\t") + 1);//去除字符串尾部的空格
	}
	return text;
}

bool check(const std::string str){
	std::string s = str;
	trim(s);
	if(s.empty()){
		return false;
	}
	return true;
}

//用于支持将多行的配置文件分割开来
void Stringsplit(std::string str, const char split, std::vector<std::string>& strList)
{
	std::istringstream iss(str);	// 输入流
	std::string token;			// 接收缓冲区
	while (getline(iss, token, split))	// 以split为分隔符
	{
		strList.push_back(token);
	}
}
//用于支持将 key=value 格式的配置文件分割开来（只分割一次）
void Stringsplit2(std::string str, const char split, std::vector<std::string>& strList)
{
	//string str = "key=value1 value2 #notes";
	size_t pos = str.find(split); // 3
	if (pos>0&&pos<str.length()) {//用于分割key=value
		std::string p = str.substr(0, pos); // 123
		std::string q = str.substr(pos + 1); // 456,789
		strList.push_back(p);
		strList.push_back(q);
	}
	else {//用于不带# 注释时的分割
		strList.push_back(str);
	}
}
//解析配置文件，并添加默认配置
std::map<std::string, std::string> get_configs(std::string fname) {
	std::string strdata;
	try {
		std::ifstream in(fname, std::ios::in);
		std::istreambuf_iterator<char> beg(in), end;
		strdata = std::string(beg, end);
		in.close();
		if (strdata.length() < 10) {
			std::cout << fname << " context is not correct! " << std::endl;
		}
	}
	catch (...) {
		std::cout <<"Read " << fname << " error! " << std::endl;
	}
 
	std::vector<std::string> strList;
	Stringsplit(strdata, '\n', strList);
	std::map<std::string, std::string> maps;
	for (size_t i = 0;i < strList.size();i++) {
		std::vector<std::string> tmp1,tmp2;
		if(!check(strList[i])) continue;
		Stringsplit2(strList[i], '#', tmp1);//用于清除注释  注释存储在trim(tmp1[1])中
		Stringsplit2(tmp1[0], '=', tmp2);//把字符串分为两节
		maps.insert({ trim(tmp2[0]),trim(tmp2[1]) });//去除字符串多余的空格（包含 \n\r\t）
	}
 
	//添加默认配置
	//如果配置文件中的key都是正常设置了的，那么下面的insert代码都不会生效
    maps.insert({ "ca_cert_path", "certs/cacert" });
    maps.insert({ "cert_path", "certs/cert" });
	maps.insert({ "rsa_sk_path", "certs/rsa_sk" });
	maps.insert({ "abe_key_path","certs/abe_key" });
	maps.insert({ "abe_pp_path", "abe_pp" });
    maps.insert({ "abe_kms_ip", "1.2.3.4" });
    maps.insert({ "abe_kms_port", "1234" });
	return maps;
}