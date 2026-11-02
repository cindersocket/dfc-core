# Host test suite for the DFC core.
#
# The core is platform-neutral; port/host supplies the platform interface so a
# workstation can run the same engine the firmware runs.
#
#   make test           all unit suites with the selected crypto backend
#   make test-backends  all unit suites with mbedTLS, then tiny-crypto-c
#   make test SANITIZE=address,undefined       under ASan and UBSan (gcc or clang)
#   make test CC=clang SANITIZE=memory         under MSan (clang, Linux only)
#   make test RELEASE=1 optimised with NDEBUG, as a shipped library is built
#
# Executable names do not encode the sanitizer, so run make clean
# between configurations.
#
CORE  := ../src
PORT  := ../port
HOST  := ../port/host

CFLAGS  += -std=c11 -Wall -Wextra -I$(CORE) -I$(PORT) -I$(HOST) -Imunit

# A release build compiles assertions out. The suite must pass either way, so
# no assertion may carry an effect the engine depends on.
RELEASE ?=
ifneq ($(strip $(RELEASE)),)
CFLAGS  += -DNDEBUG -O2
endif

CRYPTO_BACKEND  ?= mbedtls
TINY_CRYPTO_DIR ?= ../../tiny-crypto-c

ifeq ($(CRYPTO_BACKEND),mbedtls)
CFLAGS  += -DDFC_CRYPTO_BACKEND_MBEDTLS=1
LDFLAGS += -lmbedcrypto
MBEDTLS_PREFIX := $(firstword $(wildcard /opt/homebrew/opt/mbedtls@3 /usr/local/opt/mbedtls@3))
ifneq ($(MBEDTLS_PREFIX),)
CFLAGS  += -I$(MBEDTLS_PREFIX)/include
LDFLAGS += -L$(MBEDTLS_PREFIX)/lib
endif
else ifeq ($(CRYPTO_BACKEND),tiny)
ifeq ($(wildcard $(TINY_CRYPTO_DIR)/src/common.c),)
$(error tiny-crypto-c not found at $(TINY_CRYPTO_DIR); set TINY_CRYPTO_DIR)
endif
CFLAGS += -DDFC_CRYPTO_BACKEND_TINY=1 -I$(TINY_CRYPTO_DIR)/src \
	-DTC_ENABLE_AES=1 -DTC_AES_ENABLE_CBC=1 -DTC_AES_ENABLE_CTR=0 \
	-DTC_ENABLE_DES=1 -DTC_DES_ENABLE_ECB=1 -DTC_DES_ENABLE_CBC=1 -DTC_DES_ENABLE_CTR=0 \
	-DTC_DES_ENABLE_TDES=1 -DTC_ENABLE_SHA256=0
CRYPTO_SRC := $(TINY_CRYPTO_DIR)/src/common.c $(TINY_CRYPTO_DIR)/src/block_modes.c \
	$(TINY_CRYPTO_DIR)/src/aes.c $(TINY_CRYPTO_DIR)/src/aes_modes.c \
	$(TINY_CRYPTO_DIR)/src/des.c $(TINY_CRYPTO_DIR)/src/des_modes.c
else
$(error CRYPTO_BACKEND must be 'mbedtls' or 'tiny')
endif

# Sanitizers: empty (off), "address,undefined" (gcc or clang), or "memory"
# (clang on Linux). munit forks each case, so a sanitizer abort fails that
# case and its report is printed with the failure.
SANITIZE ?=
ifneq ($(strip $(SANITIZE)),)
SAN_FLAGS := -fsanitize=$(SANITIZE) -fno-omit-frame-pointer -g -O1
ifneq ($(findstring undefined,$(SANITIZE)),)
SAN_FLAGS += -fno-sanitize-recover=all
endif
ifneq ($(findstring memory,$(SANITIZE)),)
SAN_FLAGS += -fsanitize-memory-track-origins
endif
CFLAGS  += $(SAN_FLAGS)
LDFLAGS += -fsanitize=$(SANITIZE)
endif

CORE_SRC := $(wildcard $(CORE)/*.c)
HOST_SRC := $(HOST)/dfc_port_host.c $(HOST)/dfc_bytebuf_host.c
COMMON   := $(CORE_SRC) $(HOST_SRC) $(CRYPTO_SRC) munit/munit.c

VECTOR_DIRS := $(wildcard vectors/desfire/v*/emulator vectors/desfire/v*/hardware \
	vectors/desfire/v*/synthetic)
DFC_VECTORS := $(sort $(foreach directory,$(VECTOR_DIRS),$(wildcard $(directory)/*.vec)))
CONFORMANCE_RUNNER := test_dfc_conformance_vectors
CONFORMANCE_PROFILES := minimal_ev1 full_ev1 full_ev2 minimal_ev3
CONFORMANCE_PROFILE_RUNNERS := $(addprefix $(CONFORMANCE_RUNNER)_,$(CONFORMANCE_PROFILES))
CONFORMANCE_COMMON := $(CORE_SRC) dfc_vector_replay_random.c \
	$(HOST)/dfc_bytebuf_host.c $(CRYPTO_SRC)

TESTS := test_dfc_crypto test_cmac test_dfc_an10922 test_dfc_session test_dfc_secure_messaging test_dfc_desfire_protocol \
	test_munit_parameters \
	test_dfc_virtual_picc_core test_dfc_virtual_picc_secure \
	test_dfc_transaction_selection \
	test_dfc_transaction_snapshot \
	test_dfc_transaction_mac_lifecycle \
	test_dfc_transaction_mac_verify \
	test_dfc_virtual_picc_mutation_vectors test_dfc_virtual_picc_multi_app_vectors \
	test_dfc_virtual_picc_value_vectors test_dfc_ev1_conformance \
	test_dfc_file_pool test_dfc_key_pool test_dfc_der test_dfc_profile test_dfc_text \
	test_dfc_model \
	test_dfc_teardown \
	test_dfc_examples \
	test_dfc_blank_card test_dfc_picc_config test_dfc_format_picc \
	test_dfc_format_configuration test_dfc_d40_capture \
	test_dfc_command test_dfc_reader test_dfc_iso_chained_records \
	test_dfc_response \
	test_dfc_ev2_command_metadata \
	test_dfc_sdm_verify \
	test_dfc_iso_file_access \
	test_dfc_ev1_response_policy \
	test_dfc_iso_chained_records_secure test_dfc_iso_response_lifetime \
	test_dfc_iso_dep_frame_properties \
	test_dfc_effective_comm test_dfc_get_file_counters \
	test_dfc_reader_header_bounds test_dfc_decode_failure_atomicity

READER_LINK_TESTS := test_dfc_reader test_dfc_reader_header_bounds test_dfc_format_configuration

FAULT_TEST := test_cmac_failures
DES_CHAIN_FAULT_TEST := test_des_chain_failures
SECURE_MESSAGING_FAULT_TEST := test_secure_messaging_failures
AUTH_BACKEND_FAULT_TEST := test_dfc_auth_backend_failures
EV2_RESPONSE_FAULT_TEST := test_dfc_ev2_response_atomicity
SDM_FAULT_TEST := test_dfc_sdm_failures
KEY_SET_WIPE_TEST := test_dfc_roll_key_set_wipe
REDUCED_PROFILE_TEST := test_dfc_ffi_reduced_profile
REDUCED_READER_TEST := test_dfc_reader_reduced_command
REDUCED_FORMAT_TEST := test_dfc_format_picc_reduced
REDUCED_TEARDOWN_TEST := test_dfc_teardown_no_iso
LARGE_SNAPSHOT_TEST := test_dfc_transaction_snapshot_large
REDUCED_TESTS := $(REDUCED_PROFILE_TEST) $(REDUCED_READER_TEST) $(REDUCED_FORMAT_TEST) \
	$(REDUCED_TEARDOWN_TEST) $(LARGE_SNAPSHOT_TEST)

TESTS += test_dfc_ev2_capabilities test_dfc_static_signature

# Debugging tools that drive the engine from a workstation.
TOOLS := dfc_probe_apdu dfc_virtual_picc_host

# Check that each reduced build profile compiles cleanly.
PROFILES := minimal_ev1 full_ev1 full_ev2 minimal_ev3

# Link each build role under every profile, then prove from the symbol table
# that a role carries none of the parts it omits.
ROLES := target host simulator
ROLE_PROFILES := $(PROFILES) full_ev3
ROLE_DIR := role-build
FFI_ROLE_DIR := role-build/ffi
FFI_SRC := ../ffi/dfc_ffi.c ../ffi/dfc_ffi_an10922.c ../ffi/dfc_ffi_credential.c \
	../ffi/dfc_ffi_model.c ../ffi/dfc_ffi_picc.c ../ffi/dfc_ffi_reader.c \
	../ffi/dfc_ffi_response.c ../ffi/dfc_ffi_sdm.c ../ffi/dfc_ffi_transaction_mac.c
ROLE_FORBIDDEN_target := dfc_text_ dfc_reader_ dfc_command_ dfc_desfire_command_name dfc_iso_dep_control_frame_name
ROLE_FORBIDDEN_host := dfc_emulator_ dfc_virtual_picc_
ROLE_FORBIDDEN_simulator :=
CODECLESS_DIR := role-build/codecs-disabled

FUZZ_DIR  ?= ../build-fuzz
FUZZ_TIME ?= 300
FUZZ_FLAGS := -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g -O1

.PHONY: test test-backends vectors replay-plans check-replay-plans vector-parser-regressions vector-profiles test-ev2-profile test-auth-profile check-cipher-profile-matrix \
	profile-builds role-builds ffi-role-builds \
	codecs-disabled-link check-constant-time-auth check-command-modules check-command-registry check-teardown-wipes check-virtual-picc-staging check-iso-dep-block-numbers check-jni-wipes check-jni-result-buffers check-jni-export-inventory \
	check-credential-passes \
	check-decoder-registry check-random-failure-registry check-snapshot-secret-policy \
	check-secure-messaging-policy check-ffi-export-inventory \
	check-ffi-layout-registry fuzz clean

# One pattern rule serves every suite: each links the whole core, so a suite
# cannot pass by omitting the translation unit it should have exercised.
$(TESTS): %: %.c dfc_virtual_picc_test_helpers.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Suites that drive the reader against the virtual card share one fixture.
$(READER_LINK_TESTS): dfc_reader_test_link.c

# The decoder failure contract covers the target bridge's entry point too.
test_dfc_decode_failure_atomicity: ../ffi/dfc_target_ffi.c
test_dfc_decode_failure_atomicity: CFLAGS += -I../ffi

test_cmac_failures: test_cmac_failures.c $(CORE)/aes_cmac.c $(CORE)/des_cmac.c \
		$(CORE)/dfc_an10922.c munit/munit.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_des_chain_failures: test_des_chain_failures.c $(CORE)/dfc_crypto_des_chain.c munit/munit.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

FAULT_CORE_SRC := $(filter-out $(CORE)/dfc_crypto.c,$(CORE_SRC))

test_secure_messaging_failures: test_secure_messaging_failures.c \
		dfc_virtual_picc_test_helpers.c $(FAULT_CORE_SRC) $(HOST)/dfc_bytebuf_host.c munit/munit.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_dfc_auth_backend_failures: test_dfc_auth_backend_failures.c auth_fault_test_support.c \
		dfc_virtual_picc_test_helpers.c $(FAULT_CORE_SRC) $(HOST)/dfc_bytebuf_host.c munit/munit.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_dfc_sdm_failures: test_dfc_sdm_failures.c auth_fault_test_support.c \
		dfc_virtual_picc_test_helpers.c $(FAULT_CORE_SRC) $(HOST)/dfc_bytebuf_host.c munit/munit.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_dfc_ev2_response_atomicity: test_dfc_ev2_response_atomicity.c \
		$(CORE)/dfc_ev2.c $(CORE)/dfc_ev2_command.c $(CORE)/dfc_emulator_access.c munit/munit.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_dfc_roll_key_set_wipe: test_dfc_roll_key_set_wipe.c $(CORE)/dfc_credential.c \
		$(CORE)/dfc_common.c $(CORE)/aes_cmac.c $(CORE)/dfc_crypto.c $(HOST)/dfc_port_host.c \
		$(CRYPTO_SRC) munit/munit.c
	$(CC) $(CFLAGS) -o $@ test_dfc_roll_key_set_wipe.c $(CORE)/dfc_common.c $(CORE)/aes_cmac.c \
		$(CORE)/dfc_crypto.c $(HOST)/dfc_port_host.c $(CRYPTO_SRC) munit/munit.c $(LDFLAGS)

test_dfc_ffi_reduced_profile: test_dfc_ffi_reduced_profile.c $(CORE_SRC) \
		../ffi/dfc_ffi.c ../ffi/dfc_ffi_an10922.c ../ffi/dfc_ffi_credential.c \
		../ffi/dfc_ffi_model.c ../ffi/dfc_ffi_picc.c ../ffi/dfc_ffi_reader.c \
		../ffi/dfc_ffi_response.c \
		../ffi/dfc_ffi_sdm.c ../ffi/dfc_ffi_transaction_mac.c \
		../port/ffi/dfc_port_ffi.c ../port/host/dfc_bytebuf_host.c $(CRYPTO_SRC)
	$(CC) $(CFLAGS) -I../ffi -I../port/ffi \
		-DDFC_BUILD_ROLE=DFC_ROLE_TARGET \
		-DDFC_BUILD_PROFILE=DFC_PROFILE_MINIMAL_EV1 -DDFC_ENABLE_FFI=1 \
		-o $@ $^ $(LDFLAGS)

test_dfc_reader_reduced_command: test_dfc_reader_reduced_command.c $(COMMON)
	$(CC) $(CFLAGS) -DDFC_READER_MAX_COMMAND=16 -o $@ $^ $(LDFLAGS)

test_dfc_format_picc_reduced: test_dfc_format_picc.c dfc_virtual_picc_test_helpers.c $(COMMON)
	$(CC) $(CFLAGS) -DDFC_BUILD_PROFILE=DFC_PROFILE_FULL_EV1 -o $@ $^ $(LDFLAGS)

test_dfc_teardown_no_iso: test_dfc_teardown.c dfc_virtual_picc_test_helpers.c $(COMMON)
	$(CC) $(CFLAGS) -DDFC_ENABLE_ISO7816_AUTH=0 -o $@ $^ $(LDFLAGS)

test_dfc_transaction_snapshot_large: test_dfc_transaction_snapshot.c \
		dfc_virtual_picc_test_helpers.c $(COMMON)
	$(CC) $(CFLAGS) -DDFC_FILE_POOL_SIZE=65536 -DDFC_MAX_FILE_DATA=8192 \
		-DDFC_EMULATOR_CHAIN_BUFFER_SIZE=2080 -o $@ $^ $(LDFLAGS)

$(TOOLS): %: %.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: check-common-runtime check-constant-time-auth check-command-modules check-command-registry check-teardown-wipes check-virtual-picc-staging check-iso-dep-block-numbers check-jni-wipes check-jni-result-buffers check-jni-export-inventory check-virtual-picc-auth-cleanup check-credential-passes check-snapshot-secret-policy check-decoder-registry check-random-failure-registry check-secure-messaging-policy check-ffi-export-inventory check-ffi-layout-registry check-cipher-profile-matrix vectors check-replay-plans vector-parser-regressions vector-profiles $(TESTS) $(FAULT_TEST) $(DES_CHAIN_FAULT_TEST) $(SECURE_MESSAGING_FAULT_TEST) $(AUTH_BACKEND_FAULT_TEST) $(EV2_RESPONSE_FAULT_TEST) $(SDM_FAULT_TEST) $(KEY_SET_WIPE_TEST) $(REDUCED_TESTS) $(TOOLS) profile-builds role-builds ffi-role-builds codecs-disabled-link test-ev2-profile test-auth-profile
	@for t in $(TESTS); do echo "=== $$t ==="; ./$$t || exit 1; done
	./$(FAULT_TEST)
	./$(DES_CHAIN_FAULT_TEST)
	./$(SECURE_MESSAGING_FAULT_TEST)
	./$(AUTH_BACKEND_FAULT_TEST)
	./$(EV2_RESPONSE_FAULT_TEST)
	./$(SDM_FAULT_TEST)
	./$(KEY_SET_WIPE_TEST)
	@for test in $(REDUCED_TESTS); do ./$$test || exit 1; done

check-cipher-profile-matrix:
	@if [ "$(CRYPTO_BACKEND)" = "tiny" ]; then \
		DFC_TINY_CRYPTO_DIR=$(abspath $(TINY_CRYPTO_DIR)) ../scripts/check-cipher-profile-matrix.sh; \
	fi

$(CONFORMANCE_RUNNER): test_dfc_conformance_vectors.c $(CONFORMANCE_COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(CONFORMANCE_RUNNER)_%: test_dfc_conformance_vectors.c $(CONFORMANCE_COMMON)
	$(CC) $(CFLAGS) -DDFC_BUILD_PROFILE=DFC_PROFILE_$(shell echo $* | tr a-z A-Z) \
		-o $@ $^ $(LDFLAGS)

vectors: $(CONFORMANCE_RUNNER)
	@test -n "$(DFC_VECTORS)" || (echo "no DESFire conformance vectors found"; exit 1)
	./$(CONFORMANCE_RUNNER) $(DFC_VECTORS)

# Replay plans are what the language bindings run (see docs/conformance-vector-format.md).
# They are committed so no binding job needs this C runner; check-replay-plans fails
# when a vector changed without `make -C tests replay-plans`.
PLAN_DIR := replay-plans

replay-plans: $(CONFORMANCE_RUNNER)
	rm -rf $(PLAN_DIR)
	mkdir -p $(PLAN_DIR)
	./$(CONFORMANCE_RUNNER) --export-plans $(PLAN_DIR) $(DFC_VECTORS)

check-replay-plans: $(CONFORMANCE_RUNNER)
	@rm -rf $(PLAN_DIR).check && mkdir -p $(PLAN_DIR).check
	@./$(CONFORMANCE_RUNNER) --export-plans $(PLAN_DIR).check $(DFC_VECTORS) > /dev/null \
		|| { rm -rf $(PLAN_DIR).check; exit 1; }
	@diff -r $(PLAN_DIR) $(PLAN_DIR).check > /dev/null \
		|| { rm -rf $(PLAN_DIR).check; \
		echo "tests/$(PLAN_DIR) is stale: run make -C tests replay-plans"; exit 1; }
	@rm -rf $(PLAN_DIR).check

vector-parser-regressions: $(CONFORMANCE_RUNNER)
	python3 check_vector_parser.py ./$(CONFORMANCE_RUNNER)

vector-profiles: $(CONFORMANCE_PROFILE_RUNNERS)
	@for runner in $(CONFORMANCE_PROFILE_RUNNERS); do \
		./$$runner $(DFC_VECTORS) || exit 1; \
	done

check-common-runtime:
	python3 check_common_runtime.py

check-constant-time-auth:
	python3 check_constant_time_auth.py

check-command-modules:
	python3 check_command_modules.py

check-command-registry:
	python3 check_command_registry.py

check-teardown-wipes:
	python3 check_teardown_wipes.py

check-virtual-picc-staging:
	python3 check_virtual_picc_staging.py

check-iso-dep-block-numbers:
	python3 check_iso_dep_block_numbers.py

check-jni-wipes:
	python3 check_jni_wipes.py

check-jni-result-buffers:
	python3 check_jni_result_buffers.py

check-jni-export-inventory:
	python3 check_jni_export_inventory.py

check-virtual-picc-auth-cleanup:
	python3 check_virtual_picc_auth_cleanup.py

check-credential-passes:
	python3 check_credential_passes.py

check-snapshot-secret-policy:
	python3 check_snapshot_secret_policy.py

check-decoder-registry:
	python3 check_decoder_registry.py

check-random-failure-registry:
	python3 check_random_failure_registry.py

check-secure-messaging-policy:
	python3 check_secure_messaging_policy.py

check-ffi-export-inventory:
	python3 check_ffi_export_inventory.py

check-ffi-layout-registry:
	python3 ../scripts/generate-ffi-layout.py --check
	python3 test_ffi_generator.py

test_dfc_static_signature_ev2: test_dfc_static_signature.c dfc_virtual_picc_test_helpers.c $(COMMON)
	$(CC) $(CFLAGS) -DDFC_BUILD_PROFILE=DFC_PROFILE_FULL_EV2 -o $@ $^ $(LDFLAGS)

test-ev2-profile: test_dfc_static_signature_ev2
	./test_dfc_static_signature_ev2

test_dfc_der_no_iso: test_dfc_der.c dfc_virtual_picc_test_helpers.c $(COMMON)
	$(CC) $(CFLAGS) -DDFC_ENABLE_ISO7816_AUTH=0 -o $@ $^ $(LDFLAGS)

test-auth-profile: test_dfc_der_no_iso
	./test_dfc_der_no_iso /dfc_der/model-validation

test-backends:
	@$(MAKE) clean
	@$(MAKE) test CRYPTO_BACKEND=mbedtls
	@$(MAKE) clean
	@$(MAKE) test CRYPTO_BACKEND=tiny

$(FUZZ_DIR)/fuzz_dfc_codecs: fuzz_dfc_codecs.c $(CORE_SRC) $(HOST_SRC) $(CRYPTO_SRC)
	mkdir -p $(FUZZ_DIR)
	$(CC) $(CFLAGS) $(FUZZ_FLAGS) -o $@ $^ $(LDFLAGS) -fsanitize=fuzzer,address,undefined

fuzz: $(FUZZ_DIR)/fuzz_dfc_codecs
	mkdir -p $(FUZZ_DIR)/corpus $(FUZZ_DIR)/artifacts
	cp ../examples/credentials/*.dfc ../examples/credentials/*.dfcb $(FUZZ_DIR)/corpus/
	$(FUZZ_DIR)/fuzz_dfc_codecs $(FUZZ_DIR)/corpus \
		-max_total_time=$(FUZZ_TIME) -timeout=5 -artifact_prefix=$(FUZZ_DIR)/artifacts/

profile-builds:
	@echo "=== reduced profiles compile ==="
	@for p in $(PROFILES); do \
		printf "  %-14s " "$$p"; \
		$(CC) $(CFLAGS) -fsyntax-only \
			-DDFC_BUILD_PROFILE=DFC_PROFILE_$$(echo $$p | tr a-z A-Z) $(CORE_SRC) || exit 1; \
		echo ok; \
	done

role-builds:
	@echo "=== build roles link ==="
	@for r in $(ROLES); do for p in $(ROLE_PROFILES); do \
		printf "  %-10s %-14s " "$$r" "$$p"; \
		d=$(ROLE_DIR)/$$r-$$p; rm -rf $$d; mkdir -p $$d; \
		flags="-DDFC_BUILD_ROLE=DFC_ROLE_$$(echo $$r | tr a-z A-Z) -DDFC_BUILD_PROFILE=DFC_PROFILE_$$(echo $$p | tr a-z A-Z)"; \
		for src in $(CORE_SRC); do \
			$(CC) $(CFLAGS) $$flags -c $$src -o $$d/$$(basename $$src .c).o || exit 1; \
		done; \
		$(CC) $(CFLAGS) $$flags -o $$d/smoke dfc_role_smoke.c $$d/*.o $(HOST_SRC) $(CRYPTO_SRC) $(LDFLAGS) || exit 1; \
		case $$r in target) forbidden="$(ROLE_FORBIDDEN_target)";; host) forbidden="$(ROLE_FORBIDDEN_host)";; *) forbidden="$(ROLE_FORBIDDEN_simulator)";; esac; \
		for sym in $$forbidden; do \
			if nm -g $$d/*.o | grep -E " T _?$$sym" >/dev/null; then \
				echo "carries $$sym"; exit 1; \
			fi; \
		done; \
		./$$d/smoke || exit 1; \
		echo "ok ($$(cat $$d/*.o | wc -c | tr -d ' ') object bytes)"; \
	done; done

ffi-role-builds:
	@echo "=== linked FFI exports by role ==="
	@for r in $(ROLES); do \
		printf "  %-10s " "$$r"; \
		d=$(FFI_ROLE_DIR)/$$r; rm -rf $$d; mkdir -p $$d; \
		flags="-DDFC_BUILD_ROLE=DFC_ROLE_$$(echo $$r | tr a-z A-Z) -DDFC_BUILD_PROFILE=DFC_PROFILE_FULL_EV3 -DDFC_ENABLE_FFI=1"; \
		$(CC) $(CFLAGS) $$flags -I../ffi -I../port/ffi -o $$d/exports \
			test_ffi_role_exports.c $(CORE_SRC) $(FFI_SRC) ../port/ffi/dfc_port_ffi.c \
			../port/host/dfc_bytebuf_host.c $(CRYPTO_SRC) $(LDFLAGS) || exit 1; \
		./$$d/exports || exit 1; \
		python3 check_ffi_export_inventory.py --linked-image $$d/exports || exit 1; \
		echo ok; \
	done

# The model API remains linkable when both serialization formats are omitted.
# Referencing it from dfc_role_smoke makes declaration/definition guard drift a
# link failure in every test run.
codecs-disabled-link:
	@echo "=== codecs-disabled link ==="
	@rm -rf $(CODECLESS_DIR); mkdir -p $(CODECLESS_DIR); \
	flags="-DDFC_BUILD_ROLE=DFC_ROLE_TARGET -DDFC_ENABLE_DER_DECODER=0 -DDFC_ENABLE_DER_ENCODER=0 -DDFC_ENABLE_TEXT_CODEC=0"; \
	for src in $(CORE_SRC); do \
		$(CC) $(CFLAGS) $$flags -c $$src -o $(CODECLESS_DIR)/$$(basename $$src .c).o || exit 1; \
	done; \
	$(CC) $(CFLAGS) $$flags -o $(CODECLESS_DIR)/smoke dfc_role_smoke.c \
		$(CODECLESS_DIR)/*.o $(HOST_SRC) $(CRYPTO_SRC) $(LDFLAGS) || exit 1; \
	./$(CODECLESS_DIR)/smoke; \
	echo "  target, no codecs ok"

clean:
	rm -rf $(TESTS) $(FAULT_TEST) $(DES_CHAIN_FAULT_TEST) $(SECURE_MESSAGING_FAULT_TEST) $(AUTH_BACKEND_FAULT_TEST) $(EV2_RESPONSE_FAULT_TEST) $(SDM_FAULT_TEST) $(KEY_SET_WIPE_TEST) $(REDUCED_TESTS) $(TOOLS) $(CONFORMANCE_RUNNER) $(CONFORMANCE_PROFILE_RUNNERS) test_dfc_static_signature_ev2 test_dfc_der_no_iso *.dSYM $(ROLE_DIR)
