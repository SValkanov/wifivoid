wifivoid [![License](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/SValkanov/wifivoid/blob/master/LICENSE.txt)
====

Ruby script for continuously jam all wifi clients and access points within range. The effectiveness of the script depends on  your wireless card.

![fetch](https://user-images.githubusercontent.com/8790422/47272565-1f2f4a80-d590-11e8-9eb6-8f923d4f4849.png)

I've tested this well only under Ubuntu. Any feedback is welcome.

Requirements
----

Ruby version 1.9.3 or higher.

Wireless card capable of injection.

Usage
----

### Simple usage example
``` shell
ruby wifivoid.rb --adapter="wlan0"
```

Disclaimer
----

Usage of wifivoid for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
