#include "src/abe_crypto.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "gmock-global.h"
#include <fstream>
#include <string>
using std::string;

class cryptoTest : public testing::Test { // 继承了 testing::Test
protected:  
	static void SetUpTestSuite() {
    	std::cout<<"Init cryptoTest..."<<std::endl;
	} 
	static void TearDownTestSuite() {
		std::cout<<"complete."<<std::endl;
	}
	virtual void SetUp() override {
	}
	virtual void TearDown() override {
	}
	string base_dir = "./data/";
	string kms_cert_path = base_dir + "certs/kmscert.pem";
	string db_cert_path = base_dir + "certs/dbcert.pem";

	string rsa_sk_path = base_dir + "prikey/testabe@%.pem";

	string abe_key_path = base_dir + "abe/abe_key";
	string abe_pp_path = base_dir + "abe/abe_pp";
};

TEST_F(cryptoTest, cryptoInitSuccess1){
	abe_crypto crypto("testabe@%");
    bool res = crypto.init(abe_pp_path, abe_key_path, 
                    kms_cert_path, db_cert_path,
                    rsa_sk_path);
    EXPECT_EQ(true, res);//正常路径
}

TEST_F(cryptoTest, cryptoInitSuccess2){
    abe_crypto crypto("testabe@%");
	string new_path = base_dir + "non-exist-path";
    bool res = crypto.init(abe_pp_path, new_path, 
                    kms_cert_path, db_cert_path,
                    rsa_sk_path);
    EXPECT_EQ(true, res);//abe_key导入失败，但程序逻辑上允许
}

TEST_F(cryptoTest, cryptoInitFail1){
    abe_crypto crypto("testabe@%");
	string new_path = base_dir + "non-exist-path";
    bool res = crypto.init(new_path, abe_key_path, 
                    kms_cert_path, db_cert_path,
                    rsa_sk_path);
    EXPECT_EQ(false, res);//mpk导入失败
}

TEST_F(cryptoTest, cryptoInitFail3){
    abe_crypto crypto("testabe@%");
	string new_path = base_dir + "non-exist-path";
    bool res = crypto.init(abe_pp_path, abe_key_path, 
                    new_path, db_cert_path,
                    rsa_sk_path);
    EXPECT_EQ(false, res);//kms_cert导入失败
}

TEST_F(cryptoTest, cryptoInitFail4){
	abe_crypto crypto("testabe@%");
	string new_path = base_dir + "non-exist-path";
    bool res = crypto.init(abe_pp_path, abe_key_path, 
                    kms_cert_path, new_path,
                    rsa_sk_path);
    EXPECT_EQ(false, res);//db_cert导入失败
}

TEST_F(cryptoTest, cryptoInitFail5){
	abe_crypto crypto("testabe@%");
	string new_path = base_dir + "non-exist-path";
    bool res = crypto.init(abe_pp_path, abe_key_path, 
                    kms_cert_path, db_cert_path,
                    new_path);
    EXPECT_EQ(false, res);//rsa私钥导入失败
}

TEST_F(cryptoTest, cryptoSetName){
	abe_crypto crypto("testabe@%");
	crypto.set_name("test");
    EXPECT_EQ("test", crypto.user.user_id);
}

TEST_F(cryptoTest, cryptoSetAtt){
	abe_crypto crypto("testabe@%");
	crypto.set_att("test");
    EXPECT_EQ("test", crypto.user.user_attr);
}

TEST_F(cryptoTest, cryptoImportMpk){
	abe_crypto crypto("testabe@%");
	bool res;
	res = crypto.import_mpk(abe_pp_path);
	EXPECT_EQ(true, res);
	string new_path = base_dir + "non-exist-path";
    res = crypto.import_mpk(new_path);
    EXPECT_EQ(false, res);
}

TEST_F(cryptoTest, cryptoImportUserKey){
	abe_crypto crypto("testabe@%");
	bool res;
	res = crypto.import_user_key(abe_key_path);
	EXPECT_EQ(true, res);
	string new_path = base_dir + "non-exist-path";
    res = crypto.import_user_key(new_path);
    EXPECT_EQ(false, res);
}

TEST_F(cryptoTest, cryptoImportSaveKey){//todo
	
}

TEST_F(cryptoTest, cryptoCheckAbeKey){
	abe_crypto crypto("testabe@%");
	bool res;
	res = crypto.check_abe_key();
	EXPECT_EQ(false, res);
	crypto.user.user_key = "test";
	res = crypto.check_abe_key();
    EXPECT_EQ(true, res);
}

TEST_F(cryptoTest, cryptoImportDbCert){
	abe_crypto crypto("testabe@%");
	bool res;
	res = crypto.import_db_cert(db_cert_path);
	EXPECT_EQ(true, res);
	string new_path = base_dir + "non-exist-path";
    res = crypto.import_db_cert(new_path);
    EXPECT_EQ(false, res);

	res = crypto.import_db_cert(abe_key_path);//使用错误的文件格式
    EXPECT_EQ(false, res);//解析PEM文件失败
	//todo:后面两个return NULL路径怎么测？
}

TEST_F(cryptoTest, cryptoImportKmsCert){
	abe_crypto crypto("testabe@%");
	bool res;
	res = crypto.import_kms_cert(db_cert_path);
	EXPECT_EQ(true, res);
	string new_path = base_dir + "non-exist-path";
    res = crypto.import_kms_cert(new_path);
    EXPECT_EQ(false, res);

	res = crypto.import_kms_cert(abe_key_path);//使用错误的文件格式
    EXPECT_EQ(false, res);//解析PEM文件失败
	//todo:后面两个return NULL路径怎么测？
}

TEST_F(cryptoTest, cryptoImportSk){
	abe_crypto crypto("testabe@%");
	bool res;
	res = crypto.import_sk(rsa_sk_path);
	EXPECT_EQ(true, res);
	string new_path = base_dir + "non-exist-path";
    res = crypto.import_sk(new_path);
    EXPECT_EQ(false, res);//文件不存在

	res = crypto.import_sk(abe_key_path);//使用错误的文件格式
    EXPECT_EQ(false, res);//解析PEM文件失败
}

TEST_F(cryptoTest, cryptoEncAndDec){
	abe_crypto crypto("testabe@%");
	crypto.set_name("test");
	bool res = crypto.init(abe_pp_path, abe_key_path, 
                    kms_cert_path, db_cert_path,
                    rsa_sk_path);
	if(res){
		string pt, ct;
		res = crypto.encrypt("hello", "attr1 and attr2",ct);
		EXPECT_EQ(true, res);
		res = crypto.decrypt(ct, pt);
		EXPECT_EQ(true, res);
		EXPECT_EQ("hello", pt);
	}
}

TEST_F(cryptoTest, cryptoDecFail){
	abe_crypto crypto("testabe@%");
	string pt, ct;
	ct = "test";
	bool res = crypto.decrypt(ct, pt);
	EXPECT_EQ(false, res);//没有abe_key
	res = crypto.init(abe_pp_path, abe_key_path, 
                    kms_cert_path, db_cert_path,
                    rsa_sk_path);
	if(res){
		res = crypto.encrypt("hello", "attr1 and attr3",ct);
		EXPECT_EQ(true, res);
		res = crypto.decrypt(ct, pt);
		EXPECT_EQ(true, res);//属性（attr1 | attr2）不符合策略
		EXPECT_EQ("can't decrypt.", pt);//解密失败返回值
	}
}