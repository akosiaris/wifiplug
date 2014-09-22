#!/bin/sh

while true
do
	lua -e "io.stdout:setvbuf 'no'" client.lua
	sleep 45
done
