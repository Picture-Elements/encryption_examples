
sample1: sample1.c
	$(CC) -o sample1 -g sample1.c -lcrypto

pdf_public_key.zip: Makefile sample1.c  make_keys.sh
	zip pdf_public_key.zip Makefile sample1.c make_keys.sh

all: sample pdf_public_key.zip
