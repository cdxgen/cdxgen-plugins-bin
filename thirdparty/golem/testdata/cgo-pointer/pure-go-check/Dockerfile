FROM golang:1.27
# The same line as the docker-gocheck fixture, in a module with no cgo: no
# code can be affected by the knob, so there is nothing to report.
ENV GODEBUG=cgocheck=0
WORKDIR /src
COPY . .
RUN go build ./...
