CC := g++
export CXXFLAGS := -std=c++11 -lstdc++ -g -Wall -Werror -DSSL_LIB_INIT
export INCLUDE := -I/usr/include/mysql -I/usr/local/include/mysql++  -I/usr/local/include
export LDFLAGS := -L/usr/local/lib -L/usr/lib/x86_64-linux-gnu
export LDLIBS := -lmysqlpp -lmysqlclient -lcrypto -lrelic -lrelic_ec -lopenabe

MAIN_SRC := main.cpp
MAIN_OBJ := $(MAIN_SRC:%.cpp=%.o)
MAIN_EXE := abe_client

UTILS_SRCS := $(shell find src/my_utils/* -type f | grep "\.cpp")
UTILS_OBJS := $(patsubst %.cpp, %.o, $(filter %.cpp, $(UTILS_SRCS)))
SRCS := $(shell find src -maxdepth 1 -type f| grep "\.cpp")
OBJS := $(patsubst %.cpp, %.o, $(filter %.cpp, $(SRCS)))


# .PHONY: 
all:  $(MAIN_EXE)

$(MAIN_EXE): $(UTILS_OBJS) $(OBJS) $(MAIN_OBJ)
	$(CC) -o $@ $^ $(CXXFLAGS) $(INCLUDE) $(LDFLAGS) $(LDLIBS)

%.o: %.cpp
	$(CC) -c -o $@ $< $(CXXFLAGS) $(INCLUDE) $(LDFLAGS) $(LDLIBS)


clean: 
	rm -f $(MAIN_EXE) $(UTILS_OBJS) $(OBJS) $(MAIN_OBJ)

