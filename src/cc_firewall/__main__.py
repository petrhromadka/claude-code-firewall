"""Allow ``python -m cc_firewall``.

The installed hook command runs ``hook`` on every tool call, so that argv skips the CLI
module and its argparse and install imports.
"""

import sys

from cc_firewall.hook import fast_main

code = fast_main(sys.argv[1:])
if code is None:
    from cc_firewall.cli import main

    code = main()
raise SystemExit(code)
