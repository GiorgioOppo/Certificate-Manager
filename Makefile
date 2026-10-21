CC = cc
PKG_CONFIG ?= pkg-config
PYTHON ?= python3
NODE ?= node
CPPFLAGS += -D_POSIX_C_SOURCE=200809L -Isrc -Ibuild $(shell $(PKG_CONFIG) --cflags openssl sqlite3 libcurl)
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDLIBS += $(shell $(PKG_CONFIG) --libs openssl sqlite3 libcurl)
SOURCES = src/main.c src/app.c src/server.c src/certificate.c src/store.c src/chain.c src/delivery.c src/remote.c src/remote_service.c src/monitor.c src/smtp_settings.c src/lifecycle.c src/workspace.c
OBJECTS = $(SOURCES:src/%.c=build/%.o)

.PHONY: all clean test
all: certificati

certificati: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

build/assets.h: scripts/embed_assets.py web/index.html web/app.css web/app.js web/i18n.js web/server-messages.json $(wildcard web/locales/*.json)
	$(PYTHON) scripts/embed_assets.py $@

build/server.o: build/assets.h
build/%.o: src/%.c src/app.h src/certificate.h src/store.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

build/test_reminders: tests/test_reminders.c build/app.o build/store.o build/certificate.o build/chain.o build/delivery.o build/smtp_settings.o build/lifecycle.o build/workspace.o
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/test_delivery: tests/test_delivery.c build/store.o build/certificate.o build/delivery.o build/smtp_settings.o
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/test_lifecycle: tests/test_lifecycle.c build/app.o build/store.o build/certificate.o build/chain.o build/delivery.o build/smtp_settings.o build/lifecycle.o build/workspace.o build/monitor.o build/remote.o
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test: certificati build/test_reminders build/test_delivery build/test_lifecycle
	$(NODE) tests/test_i18n.cjs
	$(NODE) tests/test_inventory.cjs
	./build/test_reminders
	./build/test_delivery
	./build/test_lifecycle
	$(PYTHON) tests/integration.py
	$(PYTHON) tests/lifecycle_integration.py
	$(PYTHON) tests/workspace_integration.py
	$(PYTHON) tests/network_integration.py
	$(PYTHON) tests/remote_integration.py
	$(PYTHON) tests/monitor_integration.py
	$(PYTHON) tests/ui_pages.py
	$(PYTHON) tests/i18n_integration.py
	$(PYTHON) tests/smtp_integration.py

clean:
	rm -rf build certificati

-include $(OBJECTS:.o=.d)
