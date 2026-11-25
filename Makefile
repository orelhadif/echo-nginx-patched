# One-command entry points. Docker Desktop's CLI may not be on PATH.
export PATH := $(HOME)/.docker/bin:$(PATH)
DOCKER ?= docker
OUT    ?= out
ORIG   ?= nginx:1.25-bookworm
IMAGE  ?= echo-nginx:1.25-bookworm-patched
PYTHON ?= python3

.PHONY: all debs image test test-structure test-compat vex scan clean

## Everything: packages -> image -> tests.
all: test

## Build all .deb files from upstream source inside a clean bookworm-slim.
debs:
	DOCKER_BUILDKIT=1 $(DOCKER) build --progress=plain \
	    -f build/Dockerfile --target export \
	    --output type=local,dest=$(OUT) build/

## Build the final image from those .debs.
image: debs
	DOCKER_BUILDKIT=1 $(DOCKER) build -f Containerfile -t $(IMAGE) .

## Compare against the original image: structure, then HTTP behaviour.
test: image test-structure test-compat

test-structure:
	$(DOCKER) image inspect $(ORIG) >/dev/null 2>&1 || $(DOCKER) pull $(ORIG)
	$(PYTHON) test/compare_image.py --orig $(ORIG) --new $(IMAGE)

test-compat:
	$(DOCKER) image inspect $(ORIG) >/dev/null 2>&1 || $(DOCKER) pull $(ORIG)
	$(PYTHON) test/compat_test.py --orig $(ORIG) --new $(IMAGE)

## Bonus. Run after `make test` (they use the image it built, without rebuilding).
## Evidence from both images + VEX pinned to the CURRENT image digest. Rerun after
## every rebuild: a new digest means the old VEX no longer applies.
vex:
	vex/evidence.sh $(ORIG) $(IMAGE) > vex/evidence.txt
	$(PYTHON) vex/make_vex.py $(IMAGE)

## Rescan with Trivy + Grype, diff against scan/baseline/, scan with/without the
## VEX. Depends on `vex`, so it never scans with a VEX for an older digest.
scan: vex
	scan/run.sh $(IMAGE) $(ORIG)

clean:
	rm -rf $(OUT)
