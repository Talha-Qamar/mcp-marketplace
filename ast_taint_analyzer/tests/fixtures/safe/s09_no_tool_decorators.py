"""Safe 9: no tool decorators at all - nothing to analyse.

The function below IS vulnerable; it is simply not a tool. With
--all-functions it is reported, which is what that flag is for.
"""

import os


def helper(path):
    os.system("ls " + path)
