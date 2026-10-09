# Requirements

This file is the contract of GFE as a list of requirements, one per
feature of the README, each naming the tests that fail when it breaks.
The test `gfe/node/tests/requirements.rs` checks that every test named
here exists, so a renamed or deleted test must be renamed or replaced
here too.

## R1. Centralized TLS termination

A client gets the certificate of the name it asks for by SNI, under one
TLS policy for the fleet (minimum version, ALPN, HSTS), and a returning
client resumes its session. A certificate rotated in place on disk is
served without a restart and without dropping an established connection.

Proven by:

- `gfe/proxy/tests/tls.rs::serves_the_certificate_of_an_exact_sni`
- `gfe/proxy/tests/tls.rs::serves_a_certificate_rotated_on_disk_without_dropping_an_established_connection`
- `gfe/proxy/tests/tls.rs::a_tls13_only_policy_refuses_a_tls12_client`
- `gfe/proxy/tests/tls.rs::speaks_http2_negotiated_by_alpn_from_client_to_backend`
- `gfe/proxy/tests/tls.rs::adds_hsts_to_https_responses_only`
- `gfe/proxy/tests/tls.rs::resumes_the_session_of_a_returning_client`

## R2. L7 routing

A request is matched by its host (exact, then single-label wildcard) and
its path (exact, then longest prefix), and its route forwards it,
redirects it, or answers it with a fixed response.

Proven by:

- `gfe/proxy/tests/routing.rs::exact_host_beats_wildcard_and_catch_all`
- `gfe/proxy/tests/routing.rs::wildcard_route_matches_only_subdomains_of_its_suffix`
- `gfe/proxy/tests/routing.rs::longest_path_prefix_wins`
- `gfe/proxy/tests/routing.rs::exact_path_matches_its_route`
- `gfe/proxy/tests/routing.rs::redirect_action_names_the_same_host_and_path`
- `gfe/proxy/tests/routing.rs::fixed_action_answers_without_a_backend`

## R3. gRPC

Unary and streaming calls are proxied end to end over HTTP/2, message by
message, with their trailers, to backends over TLS or `h2c`, which are
health-checked with the gRPC health protocol. Proxy timeouts do not cut a
call, and a call GFE cannot serve fails with a proper `grpc-status`.

Proven by:

- `gfe/proxy/tests/grpc.rs::relays_a_unary_call_with_its_trailers_to_an_h2c_pool`
- `gfe/proxy/tests/grpc.rs::relays_a_unary_call_with_its_trailers_to_an_https_pool`
- `gfe/proxy/tests/grpc.rs::relays_a_bidirectional_stream_message_by_message`
- `gfe/proxy/tests/grpc.rs::a_call_silent_longer_than_upstream_first_byte_is_not_cut`
- `gfe/proxy/tests/grpc.rs::fails_a_call_to_an_unreachable_backend_with_unavailable`
- `gfe/proxy/tests/health.rs::probes_a_grpc_backend_with_the_grpc_health_service`

Not yet proven: no test checks that a call ends when its client's
deadline passes.

## R4. Upstream load balancing

A pool spreads requests with `round_robin`, `least_request` or
`ring_hash`, and only among its healthy backends.

Proven by:

- `gfe/proxy/tests/load_balancing.rs::round_robin_alternates_between_backends`
- `gfe/proxy/tests/load_balancing.rs::least_request_avoids_the_busy_backend`
- `gfe/proxy/tests/load_balancing.rs::ring_hash_keeps_a_client_on_one_backend`
- `gfe/proxy/tests/load_balancing.rs::only_healthy_backends_receive_requests`

## R5. Connection pooling

Upstream connections, HTTP/1.1 and HTTP/2, are pooled and reused. TLS to
a backend is verified against the system's trust store and an optional
extra CA, and a configured client certificate is presented.

Proven by:

- `gfe/proxy/tests/forwarding.rs::reuses_an_upstream_connection_for_sequential_requests`
- `lib/http/tests/client_pool.rs::an_http2_connection_carries_concurrent_requests`
- `lib/http/tests/client_tls.rs::the_system_store_alone_refuses_a_private_authority`
- `gfe/proxy/tests/upstream_tls.rs::sends_requests_to_an_https_pool_verified_against_the_extra_ca_over_http1`
- `gfe/proxy/tests/upstream_tls.rs::refuses_a_backend_certificate_it_does_not_trust`
- `gfe/proxy/tests/upstream_tls.rs::presents_the_configured_client_certificate`

## R6. L7 health checking

Backends are probed over TCP, HTTP, HTTPS or gRPC, change state only
after their thresholds, and are probed once however many pools share
them. A backend that fails its probe gets no requests until it passes
again.

Proven by:

- `gfe/proxy/tests/health.rs::a_backend_failing_its_probe_gets_no_requests_until_it_passes_again`
- `gfe/proxy/tests/health.rs::probes_a_grpc_backend_with_the_grpc_health_service`
- `lib/health-checking/src/probe_test.rs::tcp_probe_detects_closed_port`
- `lib/health-checking/src/probe_test.rs::http_probe_over_tls_passes_a_tls_backend`
- `lib/health-checking/src/state_machine_test.rs::transitions_after_thresholds`
- `lib/health-checking/src/checker_test.rs::probes_a_backend_shared_by_two_pools_once`

## R7. Lame-duck draining

A backend that answers its probe with the configured drain status gets
no new requests, and the requests it already has complete.

Proven by:

- `gfe/proxy/tests/health.rs::a_backend_answering_the_drain_status_finishes_its_requests_and_gets_no_new_one`
- `lib/health-checking/src/probe_test.rs::http_probe_drains_on_the_drain_status`
- `lib/health-checking/src/probe_test.rs::grpc_probe_drains_a_backend_that_is_not_serving`

## R8. Stateless + file config

A change to the dynamic config file is validated as a whole and applied
without a restart: routes, pools and listeners come and go, an invalid
config changes nothing, and no request in flight fails.

Proven by:

- `gfe/proxy/tests/reload.rs::serves_a_route_added_by_a_reload`
- `gfe/proxy/tests/reload.rs::binds_a_listener_added_by_a_reload`
- `gfe/proxy/tests/reload.rs::stops_listening_on_a_removed_listener_and_finishes_its_open_connection`
- `gfe/proxy/tests/reload.rs::no_request_fails_on_a_listener_kept_while_another_comes_and_goes`
- `gfe/proxy/tests/reload.rs::rejects_an_invalid_config_wholesale_and_keeps_serving`
- `gfe/proxy/tests/reload.rs::rejects_a_config_whose_listener_cannot_be_bound`

## R9. Last-known-good cache

A node keeps the last config it applied, and a node that starts while
its deployed config is missing or invalid serves from that cache.

Proven by:

- `gfe/proxy/tests/reload.rs::writes_the_last_known_good_cache_on_each_applied_config_only`
- `gfe/proxy/tests/reload.rs::starts_from_the_cache_when_the_deployed_config_is_missing`
- `gfe/proxy/tests/reload.rs::starts_from_the_cache_when_the_deployed_config_is_invalid`
- `gfe/node/tests/startup.rs::serves_the_cached_config_when_the_dynamic_config_is_missing`

## R10. Conservative retries

Only a bodyless idempotent request is retried, once, against another
backend, and only when no response byte has been forwarded.

Proven by:

- `gfe/proxy/tests/retries.rs::retries_a_bodyless_get_against_another_backend`
- `gfe/proxy/tests/retries.rs::does_not_retry_a_post`
- `gfe/proxy/tests/retries.rs::does_not_retry_a_get_with_a_body`
- `gfe/proxy/tests/retries.rs::retries_once_only`
- `gfe/proxy/tests/retries.rs::does_not_retry_once_the_response_has_started`

## R11. Graceful drain

On `SIGTERM` the node fails `/readyz`, stops accepting, and asks its
clients to leave (`GOAWAY` on HTTP/2, `Connection: close` on HTTP/1)
without losing a request, up to a deadline. It exits as soon as the last
client has left.

Proven by:

- `gfe/node/tests/smoke.rs::a_node_serves_its_clients_from_start_to_stop`
- `gfe/proxy/tests/drain.rs::a_draining_node_is_not_ready_accepts_nothing_and_follows_no_config_change`
- `gfe/proxy/tests/drain.rs::an_http1_request_in_flight_when_the_drain_starts_is_answered_with_connection_close`
- `gfe/proxy/tests/drain.rs::an_http2_client_is_sent_goaway_and_its_stream_in_flight_completes`
- `gfe/proxy/tests/drain.rs::the_drain_ends_as_soon_as_the_last_client_leaves`
- `gfe/proxy/tests/drain.rs::a_request_still_in_flight_at_the_deadline_is_cut_and_accounted_for`

## R12. Upgrades in place

On `SIGUSR2` the node hands its listening sockets to the binary now on
disk: no connection is refused, no request fails, and the old process
drains while its successor serves. A successor that does not start
changes nothing, and `SIGHUP` and `SIGUSR1` are ignored.

Proven by:

- `gfe/node/tests/upgrade.rs::upgrades_in_place_without_failing_a_request`
- `gfe/node/tests/upgrade.rs::readiness_probes_see_the_node_ready_throughout_an_upgrade`
- `gfe/node/tests/upgrade.rs::keeps_serving_when_its_successor_cannot_start`
- `gfe/node/tests/upgrade.rs::keeps_serving_when_its_successor_fails_after_taking_the_sockets`
- `gfe/node/tests/upgrade.rs::keeps_serving_when_sent_a_hangup`
- `gfe/node/tests/upgrade.rs::keeps_serving_when_sent_the_other_user_signal`

## R13. Observability

The node exposes Prometheus metrics on `/metrics` and its health on
`/healthz` and `/readyz`, and logs one structured event per request and
per connection when it is over. The log never holds up a request and
counts the lines it had to drop.

Proven by:

- `gfe/proxy/tests/observability.rs::access_log_describes_a_proxied_request`
- `gfe/proxy/tests/observability.rs::connection_and_access_events_of_a_connection_agree`
- `gfe/proxy/tests/grpc.rs::access_log_and_metrics_report_the_grpc_status`
- `gfe/node/tests/smoke.rs::a_node_serves_its_clients_from_start_to_stop`
- `gfe/node/tests/logging.rs::reports_how_many_log_lines_were_lost_per_destination`
- `lib/observability/src/logging_test.rs::a_destination_that_stalls_does_not_hold_up_whoever_logs`

Not yet proven: no test checks the alert rules or the dashboard against
the metrics the node exposes.

## R14. Kernel view (eBPF)

Where the node has `CAP_BPF` and `CAP_NET_ADMIN`, it reports accept-queue
wait, round-trip time, retransmissions and how connections end, per
listener and per backend. Where it cannot attach, it serves all the same
and says why.

Proven by:

- `gfe/node/tests/kernel.rs::attaches_the_kernel_view_where_it_has_the_capabilities`
- `gfe/proxy/tests/kernel.rs::reports_a_closed_client_connection_under_its_listener`
- `gfe/proxy/tests/kernel.rs::a_node_without_the_kernel_view_serves_and_says_why`
- `gfe/proxy/tests/connections.rs::the_connection_log_has_an_accept_wait_only_with_the_kernel_view`
- `lib/kernel/tests/kernel.rs::reports_both_ends_of_a_connection_closed_by_the_client`
- `gfe/proxy/src/kernel_test.rs::counts_an_upstream_connection_under_its_backend`

Not yet proven: no test checks the alert that fires when a node serves
without the kernel view.

## R15. Performance does not regress

A change does not raise the node's CPU per request on any scenario of the
end-to-end load test by more than 10% against the commit it is based on,
and finishes every scenario with no error. Proven by `hack/loadtest.sh`
run against a base commit (`./hack/loadtest.sh --against <ref>`), which
fails when a scenario regresses beyond that tolerance, and which the
`perf` workflow (`.github/workflows/perf.yml`) runs on every pull request
against its base, allowing 15% on a shared runner. The same workflow runs
the micro-benchmarks (`cargo bench`) of both commits, which say where in
the node a regression happened, and fails on a bench slower by more than
a quarter.

## R16. The build is sound

Every crate compiles without warnings, is formatted, passes clippy, its
documentation builds, and its dependencies pass the advisory, license and
source checks of `deny.toml`. Proven by the `CI` workflow
(`.github/workflows/ci.yml`), which runs on every pull request.
