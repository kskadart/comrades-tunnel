# comrades-tunnel -- Makefile wrapper around the whole workflow.
#
# All targets can run against a demo config (config/example) instead of the
# real local/ by passing CONFIG=config/example. Sudo-requiring targets print a
# one-line warning before running and are never the default of a bare target.

# Root of this repository, derived from the Makefile's own location so that
# `make -C ~/dev/comrades-tunnel <target>` works from anywhere.
ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

# Config directory to operate on (real config lives in local/, which is
# gitignored). Override per-invocation: make CONFIG=config/example <target>.
CONFIG ?= local

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^(##@|[A-Za-z0-9_.-]+:.*## )' $(MAKEFILE_LIST) | \
	awk 'BEGIN{FS=":.*##"} /^##@/{print "\n" substr($$0,5); next} NF>=2{printf "  %-20s %s\n", $$1, $$2}'

##@ Setup
.PHONY: init
init: ## Create local/ from config/example (refuses if local/ exists)
	@if [ -d "$(CONFIG)" ]; then \
		echo "ERROR: $(CONFIG) already exists; refusing to overwrite."; \
		exit 1; \
	fi
	@cp -R "$(ROOT)/config/example" "$(CONFIG)"
	@echo "Created $(CONFIG) from config/example."
	@echo "Files to edit now:"
	@for f in $$(ls "$(ROOT)/config/example"); do echo "  $(CONFIG)/$$f"; done

.PHONY: preset-ru
preset-ru: ## Copy the ru-popular preset over $(CONFIG)/direct-domains.txt (requires CONFIRM=1)
	@if [ "$(CONFIRM)" != "1" ]; then \
		echo "Refusing: this would overwrite $(CONFIG)/direct-domains.txt."; \
		echo "Re-run with CONFIRM=1 to proceed."; \
		exit 1; \
	fi
	@cp "$(ROOT)/config/presets/direct-domains.ru-popular.txt" "$(CONFIG)/direct-domains.txt"
	@echo "Copied preset to $(CONFIG)/direct-domains.txt"

##@ Generate
.PHONY: sites
sites: ## Generate the AmneziaVPN site list into build/
	@python3 "$(ROOT)/bin/gen-amnezia-sites.py" --config "$(CONFIG)"
	@echo
	@echo "Reminder: import $(ROOT)/build/amnezia-sites.json in AmneziaVPN (Split tunneling -> \"⋮\" -> \"Replace site list\") and reconnect."

.PHONY: sites-refresh
sites-refresh: ## Same, forcing a re-download of the RIPE/RIPEstat cache
	@python3 "$(ROOT)/bin/gen-amnezia-sites.py" --config "$(CONFIG)" --refresh
	@echo
	@echo "Reminder: import $(ROOT)/build/amnezia-sites.json in AmneziaVPN (Split tunneling -> \"⋮\" -> \"Replace site list\") and reconnect."

.PHONY: sites-offline
sites-offline: ## Same, without ASN expansion (--no-asn)
	@python3 "$(ROOT)/bin/gen-amnezia-sites.py" --config "$(CONFIG)" --no-asn

##@ Verify
.PHONY: check
check: ## Check the actual split routing (read-only)
	@sh "$(ROOT)/bin/check-split.sh" --config "$(CONFIG)"

.PHONY: resolvers
resolvers: ## Dry-run: what /etc/resolver files would change
	@sh "$(ROOT)/bin/install-resolvers.sh" --config "$(CONFIG)"

.PHONY: dns-guard
dns-guard: ## Dry-run: what the DNS guard would do right now
	@sh "$(ROOT)/bin/dns-guard.sh" --config "$(CONFIG)" --dry-run

.PHONY: dns-guard-status
dns-guard-status: ## Show whether the guard daemon is loaded, plus the last log lines
	@if launchctl print system/dev.comrades-tunnel.dns-guard >/dev/null 2>&1; then \
		launchctl print system/dev.comrades-tunnel.dns-guard | head -5; \
	else \
		echo "not loaded"; \
	fi
	@if [ -f /var/log/comrades-tunnel-dns-guard.log ]; then \
		tail -5 /var/log/comrades-tunnel-dns-guard.log; \
	else \
		echo "no log yet"; \
	fi

##@ Install (sudo)
.PHONY: resolvers-apply
resolvers-apply: ## Write /etc/resolver/<zone> files (sudo)
	@echo "WARNING: will write /etc/resolver/<zone> files under sudo."
	@sudo sh "$(ROOT)/bin/install-resolvers.sh" --config "$(CONFIG)" --apply

.PHONY: dns-guard-install
dns-guard-install: ## Install and start the DNS guard LaunchDaemon (sudo)
	@echo "WARNING: will install the DNS guard LaunchDaemon system-wide under sudo."
	@sudo sh "$(ROOT)/bin/install-dns-guard.sh" --config "$(CONFIG)" --apply

.PHONY: dns-guard-uninstall
dns-guard-uninstall: ## Stop and remove the DNS guard LaunchDaemon (sudo)
	@echo "WARNING: will stop and remove the DNS guard LaunchDaemon and installed files under sudo."
	@sudo sh "$(ROOT)/bin/install-dns-guard.sh" --config "$(CONFIG)" --uninstall

.PHONY: dns-reset
dns-reset: ## Reset the primary service's DNS back to DHCP (sudo)
	@service=$$(sh "$(ROOT)/bin/dns-guard.sh" --print-service); \
	if [ -z "$$service" ]; then \
		echo "ERROR: could not detect the primary network service."; \
		exit 1; \
	fi; \
	echo "Detected primary service: $$service"; \
	echo "WARNING: will reset the DNS of '$$service' back to DHCP under sudo."; \
	sudo networksetup -setdnsservers "$$service" Empty

##@ Cleanup
.PHONY: clean
clean: ## Remove generated build output, keeping the cache
	@rm -f "$(ROOT)/build/amnezia-sites.json" "$(ROOT)/build/amnezia-sites.txt"

.PHONY: clean-cache
clean-cache: ## Remove the RIPE/RIPEstat cache too
	@rm -rf "$(ROOT)/build/cache"
