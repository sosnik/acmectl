#!/bin/bash
rm -f acmectl.tar.bz2
tar -cjf acmectl.tar.bz2 . --exclude-vcs-ignores --exclude-vcs
tar -tf acmectl.tar.bz2