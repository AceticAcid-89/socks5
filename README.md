# socks5
A toy socks 5 server written in Python

`python3  server.py -i 127.0.0.1 -p 8080 -u username -w password`

`curl -v --socks5 127.0.0.1:8080 -U username:password https://zh.wikipedia.org/wiki/SOCKS`

https://rushter.com/blog/python-socks-server/