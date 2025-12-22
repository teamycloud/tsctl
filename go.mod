module github.com/teamycloud/remote-docker-agent

go 1.24

require (
	github.com/dustin/go-humanize v1.0.1
	golang.org/x/crypto v0.33.0
)

require (
	github.com/mutagen-io/mutagen v0.18.1
	golang.org/x/sys v0.30.0 // indirect
	google.golang.org/grpc v1.67.1 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
	k8s.io/apimachinery v0.21.3 // indirect
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/bmatcuk/doublestar/v4 v4.7.1 // indirect
	github.com/eknkc/basex v1.0.1 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hectane/go-acl v0.0.0-20230122075934-ca0b05cb1adb // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/mutagen-io/fsevents v0.0.0-20230629001834-f53e17b91ebc // indirect
	github.com/mutagen-io/gopass v0.0.0-20230214181532-d4b7cdfe054c // indirect
	github.com/zeebo/xxh3 v1.0.2 // indirect
	golang.org/x/net v0.35.0 // indirect
	golang.org/x/term v0.29.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241015192408-796eee8c2d53 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace k8s.io/apimachinery v0.21.3 => github.com/mutagen-io/apimachinery v0.21.3-mutagen1
