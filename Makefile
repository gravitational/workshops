CERTS := certs

.PHONY: up
up:
	docker compose up

.PHONY: clean
# Stop everything and delete all state: ./data and the k3s cluster's volume.
clean:
	docker compose down
	docker volume rm -f teleport_k3s-data
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
		duo.localhost okta.localhost entra.localhost github.localhost \
		localhost 127.0.0.1 ::1
	cp "$$(mkcert -CAROOT)/rootCA.pem" $(CERTS)/ca/mkcert-ca.pem
