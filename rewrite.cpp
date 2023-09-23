#include "rewrite.h"
using std::string;


bool parse_and_rewrite(string input, string &real_sql){
    hsql::SQLParserResult parse_result;
    hsql::SQLParser::parse(input, &parse_result);

    //似乎sqlparser不能解析类似create user xxx@xxx identified by 这类语句，这些是mysql的方言
    //只有show/select命令需要打印查询结果，其他的不需要(但show database仍然不能解析，是方言)
    //emmmm,也就是说hyrise/sql-parser主要是支持hyrise数据库，而不是mysql, 当然select还是可以的

    //todo: 解析abe_enc,abe_dec然后重写对应字段
    if (parse_result.isValid()) {
        printf("Parsed successfully!\n");
        printf("Number of statements: %lu\n", parse_result.size());

        for (auto i = 0u; i < parse_result.size(); ++i) {
            // Print a statement summary.
            hsql::printStatementInfo(parse_result.getStatement(i));
            const hsql::SQLStatement* stmt = parse_result.getStatement(i);
            switch(stmt->type()){
                case hsql::kStmtShow:
                case hsql::kStmtSelect:
                {
                    ;
                }
                    break;
                default:
                    break;
                
            }
        }
    } 
    real_sql = input;
    return true;
}