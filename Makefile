# Three commands: `make test` (build + prove), `make scan` (bonus), `make clean`.
# Docker Desktop's CLI may not be on PATH.
export PATH := $(HOME)/.docker/bin:$(PATH)
DOCKER ?= docker
OUT    ?= out
ORIG   ?= nginx:1.25-bookworm
IMAGE  ?= echo-nginx:1.25-bookworm-patched
PYTHON ?= python3

.PHONY: test scan clean

## Build the .debs (build/Dockerfile) and the image (Containerfile), then compare
## the image with the original: structure, HTTP behaviour, and the CVE attacks.
test:
	DOCKER_BUILDKIT=1 $(DOCKER) build --progress=plain -f build/Dockerfile --target export --output type=local,dest=$(OUT) build/
	DOCKER_BUILDKIT=1 $(DOCKER) build -f Containerfile -t $(IMAGE) .
	$(DOCKER) image inspect $(ORIG) >/dev/null 2>&1 || $(DOCKER) pull $(ORIG)
	$(PYTHON) test/compare_image.py --orig $(ORIG) --new $(IMAGE)
	$(PYTHON) test/compat_test.py --orig $(ORIG) --new $(IMAGE)
	$(PYTHON) test/cve_test.py --orig $(ORIG) --new $(IMAGE)

## Bonus, after `make test` (uses the image it built): evidence from both images,
## a VEX for the CURRENT image digest, then rescan with Trivy + Grype.
scan:
	$(PYTHON) vex/evidence.py $(ORIG) $(IMAGE) > vex/evidence.txt
	$(PYTHON) vex/make_vex.py $(IMAGE)
	$(PYTHON) scan/run.py $(IMAGE) $(ORIG)

clean:
	rm -rf $(OUT)
