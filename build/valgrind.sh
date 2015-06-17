#!/bin/bash

# NOTE: use to following command to send UDP datagrams to server:
#       echo -n "hello" | nc -4u -w0 127.0.0.1 9999

#valgrind --tool=memcheck --leak-check=yes --log-file=./memcheck.log ./udp_server 9998 20
valgrind --tool=helgrind --log-file=./helgrind.log ./udp_server 9998 20
#valgrind --tool=drd --log-file=./drd.log ./udp_server 9998 20
