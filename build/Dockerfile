FROM golang:1.10-alpine as builder

RUN apk add --no-cache make gcc musl-dev linux-headers
RUN apk add --update npm

ADD . /XDCchain

RUN cd /XDCchain \
    && make all \
    && chmod +x /XDCchain/build/bin/XDC

FROM alpine:latest
RUN apk add --no-cache ca-certificates bash iproute2 iputils vim
RUN apk add --update npm
WORKDIR /XDCchain

COPY --from=builder /XDCchain/build/bin/XDC /usr/local/bin/XDC
COPY --from=builder /XDCchain/build/bin/bootnode /usr/local/bin/bootnode