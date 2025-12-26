
# verify ca cert:

docker context create vm-tls --docker "host=tcp://vm1.tinyscale.com:32375,ca=/Users/jijiechen/go/src/github.com/teamycloud/tsctl/linux-bin/ca.pem,cert=/Users/jijiechen/go/src/github.com/teamycloud/tsctl/linux-bin/mac.crt,key=/Users/jijiechen/go/src/github.com/teamycloud/tsctl/linux-bin/mac.key"


# skip verify server cert:

docker context create vm-tls-skip-verify --docker "host=tcp://vm1.tinyscale.com:32375,skip-tls-verify=true,cert=/Users/jijiechen/go/src/github.com/teamycloud/tsctl/linux-bin/mac.crt,key=/Users/jijiechen/go/src/github.com/teamycloud/tsctl/linux-bin/mac.key"

start --listen 127.0.0.1:23750 --ts-server vm1.localhost:8443 --cert ./linux-bin/mac.crt --key ./linux-bin/mac.key --log-level debug