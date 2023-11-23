#include "src/rewrite.h"
#include "src/abe_crypto.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "openssl/crypto.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
using std::string;
#define private public

class rewriteTest : public testing::Test { // 继承了 testing::Test
protected:  
	static void SetUpTestSuite() {
    	std::cout<<"Init rewriteTest..."<<std::endl;
	} 
	static void TearDownTestSuite() {
		std::cout<<"complete."<<std::endl;
	}
	virtual void SetUp() override {
	}
	virtual void TearDown() override {
	}
    string base_dir = "./data/";
	string abe_key_path = base_dir + "abe/abe_key";
	string abe_pp_path = base_dir + "abe/abe_pp";
};

TEST_F(rewriteTest, needPrint){
    rewrite_plan rp("select * from company.kejibu;");
    rp.com_type = COM_SELECT;
    EXPECT_EQ(true, rp.need_print());
    rp.com_type = COM_SHOW;
    EXPECT_EQ(true, rp.need_print());

    rp.com_type = COM_SELECT_CURRENT_USER;
    EXPECT_EQ(false, rp.need_print());
    rp.com_type = COM_GET_ABE_KEY;
    EXPECT_EQ(false, rp.need_print());
    rp.com_type = COM_INSERT;
    EXPECT_EQ(false, rp.need_print());
    rp.com_type = COM_OTHER;
    EXPECT_EQ(false, rp.need_print());
    rp.com_type = WRONG_SQL;
    EXPECT_EQ(false, rp.need_print());
}

TEST_F(rewriteTest, needEnc){
    rewrite_plan rp("select * from company.kejibu;");
    EXPECT_EQ(false, rp.need_enc());
}
TEST_F(rewriteTest, needDec){
    rewrite_plan rp("select * from company.kejibu;");
    EXPECT_EQ(false, rp.need_dec());
}

TEST_F(rewriteTest, parseAndRewriteSelect){
    rewrite_plan rp("select * from company.kejibu;");
    bool res = rp.parse_and_rewrite();
    EXPECT_EQ(true, res);
    EXPECT_EQ(rp.com_type, COM_SELECT);
    EXPECT_EQ(rp.raw_sql, rp.real_sql);
    EXPECT_EQ(false, rp.need_dec());

    rp.raw_sql = "select id,abe_dec(data) from company.kejibu;";
    res = rp.parse_and_rewrite();
    EXPECT_EQ(true, res);
    EXPECT_EQ(rp.com_type, COM_SELECT);
    EXPECT_EQ("select id,data from company.kejibu;", rp.real_sql);
    EXPECT_EQ(true, rp.need_dec());

    std::vector<string> name_list = rp.field_name_list();
    EXPECT_EQ(1, name_list.size());
    EXPECT_EQ("data", name_list[0]);
}

TEST_F(rewriteTest, parseAndRewriteInsert){
    abe_crypto crypto("testabe@%");
    crypto.import_mpk(abe_pp_path);
    crypto.import_user_key(abe_key_path);


    rewrite_plan rp("insert into company.kejibu(id,data) values(1, 'messages');");
    rp.set_crypto(crypto);
    bool res = rp.parse_and_rewrite();
    EXPECT_EQ(true, res);
    EXPECT_EQ(rp.com_type, COM_INSERT);
    EXPECT_EQ(rp.raw_sql, rp.real_sql);
    EXPECT_EQ(false, rp.need_enc());

    rp.raw_sql = "insert into company.kejibu(id,data) values(1, abe_enc('hello','attr1'));";
    res = rp.parse_and_rewrite();
    EXPECT_EQ(true, res);
    EXPECT_EQ(rp.com_type, COM_INSERT);
    EXPECT_NE(rp.raw_sql, rp.real_sql);
    EXPECT_EQ(true, rp.need_enc());
}

TEST_F(rewriteTest, parseAndRewriteGetAbeKey){
    abe_crypto crypto("testabe@%");
    rewrite_plan rp("show current_abe_key;");
    rp.set_crypto(crypto);
    bool res = rp.parse_and_rewrite();
    EXPECT_EQ(true, res);
    EXPECT_EQ(rp.com_type, COM_GET_ABE_KEY);

    string expect_sql = "select owner,encrypted_key,sig_db,sig_db_type,sig_kms,sig_kms_type from mysql.abe_user_key";
    expect_sql += " where owner = '" + rp.crypto->user.user_id + "';";
    EXPECT_EQ(expect_sql, rp.real_sql);
    EXPECT_EQ(false, rp.need_enc());
}
TEST_F(rewriteTest, parseOther){
    rewrite_plan rp("show databases;");
    bool res = rp.parse_and_rewrite();
    EXPECT_EQ(true, res);
    EXPECT_EQ(rp.com_type, COM_SHOW);
    EXPECT_EQ(rp.raw_sql, rp.real_sql);

    rp.raw_sql = "select current_user();";
    res = rp.parse_and_rewrite();
    EXPECT_EQ(true, res);
    EXPECT_EQ(rp.com_type, COM_SELECT_CURRENT_USER);
    EXPECT_EQ(rp.raw_sql, rp.real_sql);

    rp.raw_sql = "create user testabe2@'%';";
    res = rp.parse_and_rewrite();
    EXPECT_EQ(true, res);
    EXPECT_EQ(rp.com_type, COM_OTHER);
    EXPECT_EQ(rp.raw_sql, rp.real_sql);

}