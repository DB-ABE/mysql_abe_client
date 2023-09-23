CXXFLAGS := -std=c++11 -lstdc++ -Wall -Werror -I/usr/include/mysql -I/usr/local/include/mysql++ -I/usr/src/sql-parser/src
LDFLAGS := -L/usr/local/lib -L/usr/lib/x86_64-linux-gnu -L/usr/src/sql-parser
LDLIBS := -lmysqlpp -lmysqlclient -lsqlparser
EXECUTABLE := main
OBJECTS := rewrite.o

all: $(EXECUTABLE)
# all:
# 	g++ $(CXXFLAGS) $(LDFLAGS) $(LDLIBS) -o hello hello.cpp
$(EXECUTABLE): $(OBJECTS)
clean: 
	rm -f $(EXECUTABLE) *.o