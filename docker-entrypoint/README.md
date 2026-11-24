These five scripts are copied verbatim from the official image's build repo,
so our image starts up exactly like `nginx:1.25-bookworm`:

    https://github.com/nginxinc/docker-nginx/tree/9abe4ae472b3332665fad9b12ee146dc242e775c/mainline/debian

That is the commit recorded in the original image's
`org.opencontainers.image.revision` annotation. `test/compare_image.py`
checks that they are byte-identical to the files inside the original image.
