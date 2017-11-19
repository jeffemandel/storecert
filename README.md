# storecert
A Java program that distributes Letsencrypt/certbot certificates stored encrypted in a Postgresql database

The motivation for this program is to be able to distribute Letsencrypt/certbot keys and certificates around to various servers that sit behind an Apache server (https://www.mydomain.net) inside a NATed domain (typically at home). I'd like to be able to use my laptop to access https://osxserver.mydomain.net whether I'm at my desk at work or on the couch at home. To do this, the same certificate that is in /etc/apache2/sites-available/osxserver.conf on www.mydomain.net be present on osxserver.mydomain.net. To do this, we use this program.

Assumptions:
1) You have set up certbot and have requested certificates for all of the machines you use
2) You have Postgresql9.5+ installed, and have two users - certbot and certuser. 
3) You have postgresql-42.1.4.jar (or later) on your classpath
4) You have JRE 8 installed (JDK if you want to compile)

The program reads its configuration from configuration.xml. There are three parameters:
certdir: Path to your live certs, typically /etc/letsencrypt/live
url: The jdbc url to your postgresql server. Something like jdbc:postgresql://localhost/certbot?user=certbot&amp;password=secret
password: A string used to encrypt the certificates in the database. We need the same password in both the server and the clients

Note that the certbot account should only be used on localhost, and this should be reflected in your pg_hba.conf. Similarly, certuser will probably only need access from your local network.

The database certstore can be created with the certbot.sql file.

The program can be compiled with
javac -cp somepath/postgresql-42.1.4.jar storecert.java

Usage
On www.mydomain.net, we look for directories inside certdir, and for all of these, grab the 4 PEM files and send them to the database:

sudo java -cp .:somepath/postgresql-42.1.4.jar storecert --store (note that we sudo, as /etc/letsencrypt/live has root ownership)

On osxserver.mydomain.net (having created /etc/letsencrypt/live/osxserver.mydomain.net if needed)

[sudo] java -cp .:somepath/postgresql-42.1.4.jar storecert --load

This will grab the certs, decrypt, and write them to the directory. It also outputs the cert in DER format in case you need this to import into a keystore.

Note that there is nothing about this that couldn't be done with scp, but it is probably a more secure approach. The program has been tested on Ubuntu 16.04 and MacOS 10.11. It isn't very tolerant of errors.


