[![Build Status](https://travis-ci.org/shove70/ice.svg?branch=master)](https://travis-ci.org/shove70/ice)
[![GitHub tag](https://img.shields.io/github/tag/shove70/ice.svg?maxAge=86400)](https://github.com/shove70/ice/releases)

# NAT, stun, turn and ice.

### Quick Start:

1: Start the Server.
```
$ cd .../ice/server
$ dub run
```
2: Start first client.
```
$ cd .../ice/examples/client
$ dub run
```
3: Start second client. (Reopen a terminal)
```
$ cd .../ice/examples/client
$ dub run
```

4: In the two client, follow the prompts to enter "menu" or other content.

5: If the tests are not normal on local host, you can deploy server on the internet public network server and modify the client configuration file at the same time.