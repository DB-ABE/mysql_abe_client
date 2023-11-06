#include "src/abe_crypto.h"
#include "gtest/gtest.h"

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
};

TEST_F(cryptoTest, temp){
    abe_crypto crypto("testabe@%");
    EXPECT_EQ(false, crypto.check_abe_key());
}