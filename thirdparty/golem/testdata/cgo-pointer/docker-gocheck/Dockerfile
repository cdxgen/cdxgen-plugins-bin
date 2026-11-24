FROM golang:1.27
# The image ships with cgo pointer checking off: the runtime reads GODEBUG
# once at start-up, and //go:debug cannot set this knob.
ENV GODEBUG=cgocheck=0
WORKDIR /src
COPY . .
RUN go build ./...
