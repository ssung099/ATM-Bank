CC = gcc

ifeq ($(CC),clang)
  STACK_FLAGS = -fno-stack-protector -Wl,-allow_stack_execute
else
  STACK_FLAGS = -fno-stack-protector -z execstack
endif

CFLAGS = ${STACK_FLAGS} -Wall -Iutil -Iatm -Ibank -Irouter -I. -I/usr/include/openssl

all: bin bin/atm bin/bank bin/router bin/init

bin:
	mkdir -p bin

bin/atm : atm/atm-main.c atm/atm.c helpers.c util/list.c
	${CC} ${CFLAGS} atm/atm.c atm/atm-main.c helpers.c util/list.c -o bin/atm -lssl -lcrypto

bin/bank : bank/bank-main.c bank/bank.c util/list.c helpers.c
	${CC} ${CFLAGS} bank/bank.c bank/bank-main.c util/list.c helpers.c -o bin/bank -lssl -lcrypto

bin/router : router/router-main.c router/router.c helpers.c
	${CC} ${CFLAGS} router/router.c router/router-main.c helpers.c -o bin/router -lssl -lcrypto

bin/init : init.c helpers.c
	${CC} ${CFLAGS} init.c helpers.c -o bin/init -lssl -lcrypto

test : util/list.c util/list_example.c util/hash_table.c util/hash_table_example.c helpers.c
	${CC} ${CFLAGS} util/list.c util/list_example.c helpers.c -o bin/list-test -lssl -lcrypto
	${CC} ${CFLAGS} util/list.c util/hash_table.c util/hash_table_example.c helpers.c -o bin/hash-table-test -lssl -lcrypto

clean:
	rm -f *.card && cd bin && rm -f *
