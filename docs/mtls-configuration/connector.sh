#!/bin/bash

# create a db with exampel data
../../../ssh-router/local-test/start-postgresql.sh

DB_NAME=tinyscale-ssh
DB_USER=tinyscale
DB_PWD=VeRyStr0ngPwd


# start connector and connect to the db
../../bin/connector --listen :8443  \
    --db-host localhost --db-port 5432 --db-user tinyscale --db-password VeRyStr0ngPwd --db-name tinyscale-ssh \
    --server-cert ./../../linux-bin/server.crt --server-key ./../../linux-bin/server.key \
    --ca-certs ./../../linux-bin/ca.pem \
    --client-cert ./../../linux-bin/connector.crt --client-key ./../../linux-bin/connector.key \
    --docker-port 32375 --host-exec-port 32090





		# listenAddr = flag.String("listen", ":8443", "Listen address for the proxy")

		# caCerts    = flag.String("ca-certs", "", "Comma-separated list of CA certificate paths")
		# clientCert = flag.String("client-cert", "", "Client certificate path for backend connections")
		# clientKey  = flag.String("client-key", "", "Client private key path for backend connections")
		
        # issuer     = flag.String("issuer", "tinyscale.com", "Expected issuer domain")

