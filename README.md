# sms-web-browsing-eecs591

This is the GitHub repository for Whale, an Internet shutdown circumvention system which allows users to access Internet content via SMS. The name is a pun on Dolphin, a state-of-the-art circumvention system which transmits data over the cellular voice channel.

```archive_utils.py``` contains simple utility functions to help with archiving webpages

```client.py``` contains our implementation of a Whale client, which can send web requests to ```webserver.py``` to perform the initial key exchange and coordinate page archives, and SMS messages to ```smsserver.py``` to retrieve the delta between the most recent archive and the current version of the webpage over SMS

```node.py``` implements abstract classes representing a Whale node (client, server, or proxy) and a Whale endpoint (client or server). In particular, these classes contain the logic for automatically sending and receiving SMS messages via a USB-connected phone and Android Debug Bridge (ADB).

```protocol.py``` defines constants for our data transmission protocol, such as header sizes, etc.

```proxy.py``` implements a simple proxy that merely forwards SMS messages between two numbers specified as a client and server.

```smsserver.py``` contains our implementation of the part of the Whale server responsible for listening to incoming SMS requests, retrieving the requested webpage from the Internet, computing the delta between the archive version specified by the client in their request, compressing the delta, and returning the result.

```webserver.py``` contains our implementation of the part of the Whale server responsible for handling the key exchange and for performing coordinated archives with a client, both of which occur over the Internet prior to a shutdown.
