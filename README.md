[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)

# IR_ThreatIntel_DomainGatherAggregator
This script was created out of the need to collect open source malicious domain(s) for use with Threat Intel application and proactive containment strategies (like DNS Sink-holing). 

---

**Table of Contents**

* [Usage](#usage)
* [Contributing](#contributing)
* [License and Copyright](#license-and-copyright)

# Usage

Produce a master file from the provided list 
```
$ cmd.exe python script.py 
```

Troubleshoot this script with an additional export of a dump of each URL and a running debug Log
```
$ cmd.exe python script.py -d 
```

Utilize your own list of domains to correlate and aggregate 
```
$ cmd.exe python script.py  - i  newListofURLS2Check.txt 
```

# Contributing

Feel free to open an issue or a PR.

# License and Copyright

Copyright(c) 2017 Kudelski Security Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 3 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
