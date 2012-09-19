#define BASIC_TEST(suite,testname,cmd) TEST(suite, testname){EXPECT_EQ(0, system(cmd));}

#define MM_TEST(suite,testname,cmd)   \
  TEST(suite, testname){              \
    int status = system(cmd);         \
    int out = 0;                      \
                                      \
    if (WIFSIGNALED(status))          \
        out = -1;                     \
  else                                \
        out = WEXITSTATUS(status);    \
                                      \
    EXPECT_FALSE(out);                \
  }


#include <gtest/gtest.h>
#include <stdlib.h>

BASIC_TEST(Feature,TC_DA_OpenBinFile , "sudo python ./disassembler_tests.py --test=TC_DA_OpenBinFile")


GTEST_API_ int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
