package mutagen_bridge

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

func compressContainerID(rawContainerId string) string {
	bytes, err := hex.DecodeString(rawContainerId)
	if err != nil {
		panic(fmt.Sprintf("Could not compress container ID: %s", rawContainerId))
	}

	base64Str := base64.StdEncoding.EncodeToString(bytes)
	// mutagen allows these chars, so we use them to make sure the converted value is able to convert back to base64
	base64Str = strings.ReplaceAll(base64Str, "=", "-")
	base64Str = strings.ReplaceAll(base64Str, "+", "_")
	base64Str = strings.ReplaceAll(base64Str, "/", ".")
	return fmt.Sprintf("0%s0", base64Str) // make sure the value begins and ends with a number
}

func decompressContainerID(compressedID string) string {
	// Remove the leading and trailing '0' added during compression
	if len(compressedID) < 2 || compressedID[0] != '0' || compressedID[len(compressedID)-1] != '0' {
		return ""
	}
	base64Str := compressedID[1 : len(compressedID)-1]

	// Reverse the character replacements
	base64Str = strings.ReplaceAll(base64Str, "-", "=")
	base64Str = strings.ReplaceAll(base64Str, "_", "+")
	base64Str = strings.ReplaceAll(base64Str, ".", "/")

	// Decode from base64
	bytes, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return ""
	}

	// Encode to hex string
	return hex.EncodeToString(bytes)
}
