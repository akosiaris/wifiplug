Introduction
============

This is a project holding all relevant code and data obtained during an investigation to the
wifiplug Android application protocol.
It is well versed for evaluation and research purposes but _should not_ be used in production.

Brief explanation of the protocol
=================================

The wifiplug Android application protocol was discovered and evaluated by chance during the
routine installation of the wifiplug Android application. This is the protocol spoken between
the various installations of the Android application around the world and a server. That specific
server is the one that talks with the plugs (their protocol has not been evaluated or even poked at)
The Android application does not talk directly with the plug.

The protocol is encrypted using 3DES and two keys. First there is a preshared key that is used to
identify the user. Obtaining the preshared key is trivial and left as an exercise to anyone feeling
the need to obtain it. After user authentication takes place (through standard username, password -
the latter being MD5 hashed and transmitted as that for some reason - procedure) a session key is
obtained and used to encrypt the rest of the conversation.

The server will periodically send status updates to the application. Those are not strictly status
updates since they will be sent anyway regardless of whether there has been any change in the state
of a plug.

Commands can be sent by the application to the server asking changes to various attributes like the
state of a plug.

Commands are (for some reason) enclosed in the strings 'BBBB' (BEGIN ??) and 'EEEE' (END ??) and are
identified by a single number (1,2,3 etc). So for example 5 is the idle command, 1 is the login command etc

Language
========

Lua. Why? Because it started as a PoC wireshark dissector and then a PoC client was
developped on top of it.

Parts
=====

The projects is split into 3 parts

Common code
-----------

The library of common functions, variables used by both the dissector and the client. This
resides in wifiplug\_common.lua

Wireshark dissector
-------------------

Residing in wifiplug.lua is the code used to have wireshark dissect successfully the processed
packets and display all the needed data

client application
------------------

The client application simulates a few very specific aspects of the Android application. Namely it
is capable of login in (but not logging out!), parsing the status updates sent by the server and write
them to a CSV file and scheduling the toggling on/off of known plugs through a Google cal scheduler

How To Use
==========

Just:

	git clone the repo
	cp client\_config.lua.dist file client\_config.lua.

Edit client\_config.lua and adjust the settings to match your own, then run run.sh

	./run.sh

For the Google Calendar
=======================

For the Google Calendar scheduling function,

* Write down the MACs of your plugs
* log in to Google Calendar
* create a new calendar
* make sure it has the same timezone as where you will be deploying the code
* create events with whatever names and scheduling you feel like and then add lines like the following in the description

	aabbccddeeff,ON

	112233445566,OFF

* Any lines not conforming to the above will be disregarded. _PLEASE DO NOT_ enter the same MAC twice. The last specified one is
bound to be the one happening so it _WILL_ confuse you.
* Go in to the calendars settings and copy paste the private link of the Calendar to the gcal\_url setting
* run run.sh

FAQ
===

* Q: shared objects (.so) in the repo ? Are you insane ?
* A: I wanted to have something working fast. alarm and openssl only existed in C extensions for Lua so I compiled them for
debian wheezy. They also work for Ubuntu 12.04.3 LTS. Feel free to recompile your own. Even better feel free to package them for
your favourite OS

* Q: Will the client be hitting the Google Calendar private link often ?
* A: Once every 60 seconds. It is locally cached and you can always adjust scheduler\_timer to something more to your liking

* Q: This is not a daemon!
* A: Yes I know, no plans to really daemonize the client

* Q: What does run.sh do?
* A: It provides an easy way to restart the application if it crashes. It is meant to be run in a screen command

* Q: How about the master 3DES key ?
* A: I wont be providing it publicly for security reasons. Feel free to discover it yourself though.
