# The demo's traffic generator: curl for HTTP(S), grpcurl for gRPC, and a
# shell script that mixes them.
FROM fullstorydev/grpcurl:latest AS grpcurl

FROM alpine:3.22
# iproute2 provides `tc`, to degrade a client's network on purpose.
RUN apk add --no-cache curl iproute2
COPY --from=grpcurl /bin/grpcurl /usr/local/bin/grpcurl
COPY traffic.sh /traffic.sh
ENTRYPOINT ["/bin/sh", "/traffic.sh"]
