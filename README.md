# simpleKerberos
Simple kerberos key server application. Contains a keyserver for authenticating/exchanging public keys securely, a user server for opening up a port to listen on, and sends an encrypted session to the user client. The user client further decrypts the session key, and both the user server and user client use the same session key to communicate securely over a socket connection.
