all:
	gcc httpauth.c tcp_client.c -o app
	@rm -f *.o *.mod.o *.mod.c *.symvers *.markers *~ *.order
	
clean:
	@rm -f *.ko *.o *.mod.o *.mod.c *.symvers *.markers *~ *_app *.order
