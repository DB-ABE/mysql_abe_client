#include "src/parameters.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "openssl/crypto.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
using std::string;

class parametersTest : public testing::Test { // 继承了 testing::Test
protected:  
	static void SetUpTestSuite() {
    	std::cout<<"Init parametersTest..."<<std::endl;
	} 
	static void TearDownTestSuite() {
		std::cout<<"complete."<<std::endl;
	}
	virtual void SetUp() override {
	}
	virtual void TearDown() override {
	}
};

TEST_F(parametersTest, paramReadOpt){
    bool res;
    parameters params;
    int argc1 = 5;
    const char *argv1[] = {"abe_client", "-u", "testabe" , "-p", "123456"};
    res = read_opt(params, argc1, (char**)argv1);
    EXPECT_EQ(true, res);

    int argc2 = 3;
    const char *argv2[] = {"abe_client", "-u", "testabe"};
    EXPECT_EXIT(read_opt(params, argc2, (char**)argv2), testing::ExitedWithCode(0), "error");

    int argc21 = 3;
    const char *argv21[] = {"abe_client", "-p", "123456"};
    EXPECT_EXIT(read_opt(params, argc21, (char**)argv21), testing::ExitedWithCode(0), "error");
    
    int argc3 = 7;
    const char *argv3[] = {"abe_client","-u", "testabe" , "-p", "123456", "-a", "testabe"};//-a选项不存在
    res = read_opt(params, argc3, (char**)argv3);
    EXPECT_EQ(true, res);

    int argc4 = 2;
    const char *argv4[] = {"abe_client", "--help"};
    EXPECT_EXIT(read_opt(params, argc4, (char**)argv4), testing::ExitedWithCode(0), "");
}

TEST_F(parametersTest, paramReadConfigFile){
    parameters params;
    bool res = read_config_file(params);
    EXPECT_EQ(true, res);
}