
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile
	$(MAKE) -f objs/Makefile manpage

install:
	$(MAKE) -f objs/Makefile install

upgrade:
	/usr/local/nginx-1/sbin/nginx -t

	kill -USR2 `cat /usr/local/nginx-1/logs/nginx.pid`
	sleep 1
	test -f /usr/local/nginx-1/logs/nginx.pid.oldbin

	kill -QUIT `cat /usr/local/nginx-1/logs/nginx.pid.oldbin`
