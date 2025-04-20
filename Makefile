share_via_http: share_via_http.c
	gcc -g3 -o share_via_http share_via_http.c -lmicrohttpd -lqrencode -DUSE_QRCODE
