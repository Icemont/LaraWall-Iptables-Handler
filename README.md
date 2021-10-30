# LaraWall Iptables Handler

[![Version](https://poser.pugx.org/icemont/larawall-iptables-handler/version)](//packagist.org/packages/icemont/larawall-iptables-handler)
[![License](https://poser.pugx.org/icemont/larawall-iptables-handler/license)](//packagist.org/packages/icemont/larawall-iptables-handler)


[LaraWall](https://github.com/Icemont/LaraWall) rule handler for Iptables.
Receives data from the [LaraWall](https://github.com/Icemont/LaraWall) instance via API and manages Linux netfilter firewall rules using the Iptables utility.

## Disclamer!
The handler is currently only tested on Linux distributions based on Debian!

This handler is fully functional, but because it is designed only as an example of handling rules from a LaraWall instance on a target server, it may have architectural flaws. For example, to import rules from API, it is preferable to use [DTO](https://en.wikipedia.org/wiki/Data_transfer_object).


## System Requirements
The handler script needs to be run by a user with **root** privileges.

The system must have the iptables and ipset utilities installed.

For the firewall rules to work (restrict/allow access to server service ports) created by the handler, the default Iptables policy for the `INPUT` chain must be `DROP`.

## Installation

	$ composer create-project icemont/larawall-iptables-handler

After installation, set the handler settings in config/config.php

_Note: if you installed the handler manually, you will need to copy the config/config.php file manually from the config/config.sample.php file._

Run the handler as root user and make sure there are no errors. Then add the script to the crontab task scheduler (as root):

`* * * * * php /path-to-your-project/handler.php >> /dev/null 2>&1`

## Contact

Open an issue on GitHub if you have any problems or suggestions.

## License

The contents of this repository is released under the [MIT license](https://opensource.org/licenses/MIT).
