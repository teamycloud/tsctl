package utils

import (
	"errors"
	"io"
)

func CopyBiDirectional(first, second io.ReadWriteCloser) error {
	defer first.Close()
	defer second.Close()

	var allErrors []error
	// Bidirectional copy for the rest of the connection
	errChan := make(chan error, 2)

	// Client -> Backend (remaining data)
	go func() {
		_, err := io.Copy(first, second)
		errChan <- err
	}()

	// Backend -> Client
	go func() {
		_, err := io.Copy(second, first)
		errChan <- err
	}()

	// Wait for either direction to complete
	err1 := <-errChan
	allErrors = append(allErrors, err1)

	// Wait for the second goroutine
	err2 := <-errChan
	allErrors = append(allErrors, err2)
	return errors.Join(allErrors...)
}

func CopyWithSplitMerge(biDirectionalStream io.ReadWriteCloser, reader io.Reader, writer io.WriteCloser) error {
	defer writer.Close()
	defer biDirectionalStream.Close()

	var allErrors []error
	errChan := make(chan error, 2)

	// Reader -> biDirectionalStream
	go func() {
		_, err := io.Copy(biDirectionalStream, reader)
		// Close write side to signal EOF to the other end
		if closeWriter, ok := biDirectionalStream.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
		errChan <- err
	}()

	// biDirectionalStream -> writer
	go func() {
		_, err := io.Copy(writer, biDirectionalStream)
		errChan <- err
	}()

	// Wait for both goroutines to complete
	err1 := <-errChan
	allErrors = append(allErrors, err1)

	err2 := <-errChan
	allErrors = append(allErrors, err2)
	return errors.Join(allErrors...)
}
