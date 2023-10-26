export CXXFLAGS := -std=c++11 -lstdc++ -g -Wall -Werror -I/usr/include/mysql -I/usr/local/include/mysql++ -DSSL_LIB_INIT  -I/usr/local/include
export LDFLAGS := -L/usr/local/lib -L/usr/lib/x86_64-linux-gnu
export LDLIBS := -lmysqlpp -lmysqlclient -lcrypto -lrelic -lrelic_ec -lopenabe
EXECUTABLE := main test
OBJECTS := rewrite.o abe_crypto.o parameters.o
UTIL_OBJECTS := config.o base64.o
# .PHONY: my_utils_tag
all:  $(EXECUTABLE)

# my_utils_tag:
# 	$(MAKE) -C my_utils
parameters.o: my_utils/config.o my_utils/base64.o
	g++ -std=c++11 -lstdc++ -g -Wall -Werror parameters.cpp -c -o $@
my_utils/config.o:
	g++ -std=c++11 -lstdc++ -g -Wall -Werror my_utils/config.cpp -c -o my_utils/config.o
my_utils/base64.o:
	g++ -std=c++11 -lstdc++ -g -Wall -Werror my_utils/base64.cpp -c -o my_utils/base64.o



# all:
# 	g++ $(CXXFLAGS) $(LDFLAGS) $(LDLIBS) -o hello hello.cpp
$(EXECUTABLE): my_utils/config.o my_utils/base64.o  $(OBJECTS) 
clean: 
	rm -f $(EXECUTABLE) *.o my_utils/*.o
# $(MAKE) -C my_utils clean