module github.com/teamycloud/tsctl

go 1.24

require (
	github.com/dustin/go-humanize v1.0.1
	github.com/fsnotify/fsnotify v1.9.0
	github.com/jackc/pgx/v5 v5.7.6
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.8.1
	golang.org/x/crypto v0.37.0
)

require (
	github.com/mutagen-io/mutagen v0.18.1
	golang.org/x/sys v0.32.0 // indirect
	google.golang.org/grpc v1.67.1 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
	k8s.io/apimachinery v0.21.3 // indirect
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/bmatcuk/doublestar/v4 v4.7.1 // indirect
	github.com/eknkc/basex v1.0.1 // indirect
	github.com/fatih/color v1.17.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hectane/go-acl v0.0.0-20230122075934-ca0b05cb1adb // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mutagen-io/fsevents v0.0.0-20230629001834-f53e17b91ebc // indirect
	github.com/mutagen-io/gopass v0.0.0-20230214181532-d4b7cdfe054c // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/zeebo/xxh3 v1.0.2 // indirect
	golang.org/x/net v0.35.0 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/term v0.31.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241015192408-796eee8c2d53 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace k8s.io/apimachinery v0.21.3 => github.com/mutagen-io/apimachinery v0.21.3-mutagen1

replace github.com/mutagen-io/mutagen v0.18.1 => github.com/teamycloud/mutagen v0.18.1-tinyscale2
