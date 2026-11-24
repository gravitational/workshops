CERTS := certs

TELEPORT_VERSION ?= 19.0.1
TELEPORT_IMAGE ?= public.ecr.aws/gravitational/teleport-ent-distroless-debug:$(TELEPORT_VERSION)
export TELEPORT_IMAGE

.PHONY: up
up:
	docker compose up

.PHONY: down
down:
	docker compose down

.PHONY: stop
stop:
	docker compose stop

.PHONY: clean
clean:
	rm -fr ./data

.PHONY: certs
# Browser-trusted TLS for every *.localhost service. Installs mkcert's CA into
# your system (and Firefox, if nss is installed) trust stores, issues one cert
# for all names, and copies the CA cert (never its key) for containers to trust.
certs:
	mkcert -install
	mkdir -p $(CERTS)/ca
	mkcert -cert-file $(CERTS)/localhost.pem -key-file $(CERTS)/localhost-key.pem \
		teleport.localhost '*.teleport.localhost' \
		duo.localhost okta.localhost entra.localhost \
		localhost 127.0.0.1 ::1
	cp "$$(mkcert -CAROOT)/rootCA.pem" $(CERTS)/ca/mkcert-ca.pem
