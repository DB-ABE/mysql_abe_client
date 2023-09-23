#include "SQLParser.h"
#include "util/sqlhelper.h"
#include <string>
#include <iostream>

using std::string;
/*
* input: 用户输入的原始sql语句
* real_sql: 重写完成后真正要执行的sql语句
*/
bool parse_and_rewrite(string input, string &real_sql);
