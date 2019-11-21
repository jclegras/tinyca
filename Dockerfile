FROM golang:alpine AS builder
RUN apk update && apk add --no-cache git
WORKDIR $GOPATH/src/github.com/jclegras/tinyca/
COPY . .
RUN go get -d -v
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /go/bin/tinyca .


FROM alpine:latest  
EXPOSE 8080
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /go/bin/tinyca ./app
CMD ["./app"]  
