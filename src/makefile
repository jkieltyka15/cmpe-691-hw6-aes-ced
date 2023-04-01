TDIR = ../test
AES = $(TDIR)/aes-ced.a

VERILOG = iverilog
FLAGS = -g2012

$(mkdir -p $TDIR)

all: aesced

aesced:
	$(VERILOG) $(FLAGS) aes_ced_tb.v -o $(AES)

clean:
	rm -f $(TDIR)/*.a