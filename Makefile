export CXXFLAGS := -std=c++11 -lstdc++ -Wall -Werror -I/usr/include/mysql -I/usr/local/include/mysql++ -DSSL_LIB_INIT  -I/usr/local/include
export LDFLAGS := -L/usr/local/lib -L/usr/lib/x86_64-linux-gnu
export LDLIBS := -lmysqlpp -lmysqlclient -lcrypto -lrelic -lrelic_ec -lopenabe
EXECUTABLE := main test
OBJECTS := rewrite.o abe_crypto.o parameters.o
UTIL_OBJECTS := config.o
# .PHONY: my_utils_tag
all:  $(EXECUTABLE)

# my_utils_tag:
# 	$(MAKE) -C my_utils
parameters.o: my_utils/$(UTIL_OBJECTS) 
	g++ -std=c++11 -lstdc++ -Wall -Werror parameters.cpp -c -o $@
my_utils/$(UTIL_OBJECTS): my_utils/config.cpp
	g++ -std=c++11 -lstdc++ -Wall -Werror $^ -c -o $@


# all:
# 	g++ $(CXXFLAGS) $(LDFLAGS) $(LDLIBS) -o hello hello.cpp
$(EXECUTABLE): my_utils/$(UTIL_OBJECTS)  $(OBJECTS) 
clean: 
	rm -f $(EXECUTABLE) *.o my_utils/*.o
# $(MAKE) -C my_utils clean