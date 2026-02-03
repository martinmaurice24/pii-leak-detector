package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
)

var (
	SourceFilePathWasEmptyErr           = errors.New("source file path was empty")
	FailedToCreateReqWithSourceGivenURL = errors.New("failed to create request with given url")
	SourceGivenURLReqErr                = errors.New("failed to request source url")
	SourceTypeIsUnknownErr              = errors.New("source type is unknown")
)

type SourceType int

const (
	FileSource = iota
	URLSource
	StringSource
)

func (st SourceType) String() string {
	return [...]string{"FileSource", "URLSource", "StringSource"}[st]
}

type Source struct {
	SourceType SourceType
	FilePath   string
	URL        string
	Content    string
}

func (s Source) readFromFile() ([]byte, error) {
	if s.FilePath == "" {
		return nil, SourceFilePathWasEmptyErr
	}
	return os.ReadFile(s.FilePath)
}

func (s Source) readFromURL(ctx context.Context) ([]byte, error) {
	logger := slog.With("url", s.URL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		logger.Error(FailedToCreateReqWithSourceGivenURL.Error(), "err", err)
		return nil, errors.Join(FailedToCreateReqWithSourceGivenURL, err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Error(SourceGivenURLReqErr.Error(), "err", err)
		return nil, errors.Join(FailedToCreateReqWithSourceGivenURL, err)
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func (s Source) readFromString() ([]byte, error) {
	return []byte(s.Content), nil
}

func (s Source) Read(ctx context.Context) ([]byte, error) {
	switch s.SourceType {
	case FileSource:
		return s.readFromFile()
	case URLSource:
		return s.readFromURL(ctx)
	case StringSource:
		return s.readFromString()
	default:
		return nil, SourceTypeIsUnknownErr
	}
}
