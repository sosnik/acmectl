# acme-hooked Hook Scripts

The acme-hooked script clearly separates concerns into two categories: (1)
handling the communication with the ACME server, and (2) modifying your local
system (e.g. to make challenges available to the ACME server, or updating
certificates, once they are issued). Point (2) is handled by hook scripts. These
can be written in any language that runs on your system. acme-hooked calls these
hook scripts at appropriate points in the code and issues the commands listed in
this file.

## The Command-line Interface for Hook Scripts

Hook scripts need to implement the following command-line interface:

### `/path/to/hookscript setup <domain> <token> <content>`

This command is executed when an ACME challenge needs to be set up. It contains
the domain name that needs to complete the challenge, the ACME challenge token,
and the content of the challenge.

It should set up the challenge in the appropriate way so that the ACME server
can later verify it by contacting your server via the internet.

### `/path/to/hookscript activate`

This command is executed when all ACME challenges have been set up and can now be
made accessible to the ACME server for verification.

### `/path/to/hookscript check <domain> <token> <content>`

This command is executed when an ACME challenge needs to checked, before the ACME
server is notified of challenge completion. It contains the domain name that
needs to complete the challenge, the ACME challenge token, and the content of
the challenge.

It should verify that the challenge is indeed accessible over the internet and
gives the correct result. A wait timer (e.g. to wait for DNS propagation) can be
implemented here.

### `/path/to/hookscript remove <domain> <token> <content>`

This command is executed when an ACME challenge needs to be removed after it was
completed. It contains the domain name that needs to complete the challenge, the
ACME challenge token, and the content of the challenge.

It should remove the challenge so that it is no longer stored anywhere, or, at
least, no longer accessible from the internet.

### `/path/to/hookscript finish`

This command is executed when all ACME challenges have been completed and removed.
It offers the opportunity to do final cleanup work.

### `/path/to/hookscript write <csrfile>`

This command is executed when a certificate for a given CSR has been
successfully issued. It contains the name of the CSR file as a parameter. The
certificate contents are supplied via stdin.

This command should store the certificate in an appropriate location so that
they can subsequently be used by your webserver (or other TLS-secured service).
