#!/bin/bash

inform() {
    echo "--------------------------------------------------------------------------------"
    echo "$@"
    echo "--------------------------------------------------------------------------------"
}

clear
cat <<EOB
This script is now deprecated.

GLAuth no longer uses plugins - database support is now embedded directly in the main binary.

Please use the Makefile targets instead:

make builddocker
make testdocker

EOB
exit 0
