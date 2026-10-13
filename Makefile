CC=gcc
CFLAGS=-Wall -Wextra -O2
TARGET=seccage
SRC=src/seccage.c src/policy.c src/limits.c
TESTS=test_static file_test_static network_test_static cpu_test_static memory_test_static fd_limit_test_static identity_test_static cap_test_static netns_test_static escape_test_static

all: $(TARGET)
$(TARGET): $(SRC) src/policy.h src/limits.h
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)
tests:
	@for f in test file_test network_test cpu_test memory_test fd_limit_test identity_test cap_test netns_test escape_test; do \
	  $(CC) -static src/$$f.c -o $${f}_static || exit 1; \
	done
clean:
	rm -f $(TARGET) *_static
.PHONY: all tests clean
