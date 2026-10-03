#!/bin/sh
# Endless, deliberately messy client traffic against the demo GFE: mostly
# healthy requests, plus the failures an edge proxy sees every day, so that
# every panel and every log field has something to show.
#
# Each iteration picks one scenario at random. WORKERS loops run in parallel.

GFE="${GFE:-gfe}"
WORKERS="${WORKERS:-4}"

# rand N: a number in [0, N).
rand() { echo $((RANDOM % $1)); }

# One of a handful of user agents, so the access log has clients to tell apart.
agent() {
    case $(rand 5) in
        0) echo "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0" ;;
        1) echo "Mozilla/5.0 (Macintosh) Safari/605.1.15" ;;
        2) echo "python-requests/2.32.3" ;;
        3) echo "okhttp/4.12.0" ;;
        *) echo "Go-http-client/2.0" ;;
    esac
}

# HTTPS (HTTP/2) to the given host and path; SNI and Host are the demo name,
# the connection goes to the GFE container.
https() { host=$1; path=$2; shift 2
    curl -sk -o /dev/null -A "$(agent)" --connect-to "::$GFE:8443" "$@" "https://$host:8443$path"
}

# Plaintext HTTP/1.1.
http() { host=$1; path=$2; shift 2
    curl -s -o /dev/null -A "$(agent)" -H "Host: $host" "$@" "http://$GFE:8080$path"
}

# A gRPC call through the plaintext gRPC listener.
grpc() { authority=$1; method=$2; shift 2
    grpcurl -plaintext -authority "$authority" "$@" "$GFE:9000" "$method" >/dev/null 2>&1
}

scenario() {
    case $(rand 100) in
        # --- healthy traffic (about two thirds) -------------------------------
        [0-9]|1[0-9])     https shop.demo.local "/get" ;;
        2[0-4])           https shop.demo.local "/bytes/$(( $(rand 200) * 1024 ))" ;;
        2[5-9])           https shop.demo.local "/api/anything/orders/$(rand 500)" ;;
        3[0-7])           https api.demo.local  "/anything/users/$(rand 1000)" ;;
        3[8-9]|4[0-3])    head -c "$(( $(rand 64) * 1024 + 1 ))" /dev/urandom |
                              https api.demo.local "/post" -X POST --data-binary @- \
                                  -H "Content-Type: application/octet-stream" ;;
        4[4-7])           http  api.demo.local  "/anything/internal" ;;
        4[8-9])           # several requests over one kept-alive connection
                          curl -sk -o /dev/null -o /dev/null -o /dev/null -A "$(agent)" \
                              --connect-to "::$GFE:8443" \
                              "https://shop.demo.local:8443/uuid" \
                              "https://shop.demo.local:8443/headers" \
                              "https://shop.demo.local:8443/ip" ;;
        5[0-3])           https media.demo.local "/" ;;      # one backend flaps
        5[4-5])           http  any.demo.local   "/ping" ;;  # fixed response
        5[6-7])           http  shop.demo.local  "/" ;;      # redirect to https
        5[8-9])           https api.demo.local   "/delay/1" ;;   # slow but fine
        6[0-5])           grpc greeter.demo.local helloworld.Greeter/SayHello -d '{"name":"demo"}' ;;
        6[6-8])           grpc grpcbin.demo.local grpcbin.GRPCBin/DummyUnary -d '{"f_string":"demo"}' ;;
        69|70)            grpc grpcbin.demo.local grpcbin.GRPCBin/DummyServerStream -d '{"f_string":"demo"}' ;;

        # --- what backends get wrong ------------------------------------------
        7[1-3])           https shop.demo.local "/status/404" ;;
        7[4-5])           https api.demo.local  "/status/500" ;;
        76)               https api.demo.local  "/status/503" ;;
        7[7-8])           https api.demo.local  "/delay/5" ;;    # no answer in time: 504
        79|80)            grpc grpcbin.demo.local grpcbin.GRPCBin/SpecificError -d "{\"code\":$(( $(rand 16) + 1 ))}" ;;
        8[1-3])           http  legacy.demo.local "/" ;;          # backend is gone
        84)               grpc grpc-legacy.demo.local helloworld.Greeter/SayHello -d '{"name":"demo"}' ;;

        # --- what clients get wrong -------------------------------------------
        8[5-7])           https shop.demo.local "/delay/2" --max-time 1 ;;    # gives up early: 499
        8[8-9])           https shop.demo.local "/drip?duration=4&numbytes=4000&delay=0" --max-time 1 ;;  # leaves mid-body
        9[0-2])           https nowhere.demo.local "/" ;;                     # no such route: 404
        9[3-4])           curl -s -o /dev/null --max-time 2 "http://$GFE:8443/" ;;   # plain HTTP to the TLS port
        9[5-6])           curl -s -o /dev/null --connect-to "::$GFE:8443" "https://shop.demo.local:8443/" ;;  # does not trust the cert
        *)                # a client that only speaks TLS 1.1
                          curl -sk -o /dev/null --tls-max 1.1 --ciphers "DEFAULT@SECLEVEL=0" \
                              --connect-to "::$GFE:8443" "https://shop.demo.local:8443/" ;;
    esac
}

worker() {
    while true; do
        scenario
        # 20 to 220 ms between requests.
        sleep "0.$(printf '%02d' $(( $(rand 20) + 2 )))"
    done
}

echo "traffic: $WORKERS workers against $GFE"
i=0
while [ "$i" -lt "$WORKERS" ]; do
    worker &
    i=$((i + 1))
done
wait
