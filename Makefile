CFLAGS		= -pipe -Wall -O2 -ggdb -g3
LDLIBS		= -lpcap -lcrypto
PROG		= eapmd5pass
PROGOBJ		= utils.o
PROGDSYM    = eapmd5pass.dSYM

all: $(PROGOBJ) $(PROG) 

utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -c utils.c

eapmd5pass: eapmd5pass.c eapmd5pass.h utils.c utils.h
	$(CC) $(CFLAGS) -o eapmd5pass $(PROGOBJ) eapmd5pass.c $(LDLIBS)

clean:
	$(RM) $(PROG) $(PROGOBJ) *~
	$(RM) -r $(PROGDSYM)

strip:
	@strip $(PROG)
