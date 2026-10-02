# Amber per-project container for the gittuf research artifact.
#
# Run-model = the `amber` CLI (ENTRYPOINT), exactly like the generic Amber
# container (darnit_reproducibility.research.container.DEFAULT_DOCKERFILE), but
# this image also carries everything the gittuf benchmark needs to run and be
# live-captured by witness inside the container:
#   * Go toolchain  -> builds the gittuf binary from source
#   * gittuf        -> the artifact under test (built from the vendored source)
#   * witness       -> the capture backend amber wraps (vendored, verified; no download)
#   * amber         -> installed from local source (darnit-core + darnit-reproducibility)
#
# The build context (assembled by run_gittuf_amber.py) is laid out as:
#   Dockerfile
#   witness/      (copy of packaging/container/vendor/witness/)
#   packages/     (copy of packages/darnit and packages/darnit-reproducibility)
#   gittuf-src/   (the unpacked gittuf source tree, contains main.go + go.mod)
FROM python:3.12-slim-bookworm

ARG GO_VERSION=1.27.1
ARG WITNESS_VERSION=0.12.0
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates openssl xz-utils tar openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Go toolchain (builds gittuf). -buildvcs=false: the copied source carries no .git.
RUN curl -sSfL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}" \
    GOFLAGS=-buildvcs=false \
    GOTOOLCHAIN=auto

# witness (in-toto) — vendored release, verified against upstream checksums. No network.
COPY witness/ /tmp/witness/
RUN cd /tmp/witness \
    && grep "witness_${WITNESS_VERSION}_linux_amd64.tar.gz$" "witness_${WITNESS_VERSION}_checksums.txt" | sha256sum -c - \
    && tar -xz -C /usr/local/bin -f "witness_${WITNESS_VERSION}_linux_amd64.tar.gz" witness \
    && rm -rf /tmp/witness \
    && witness version

# amber — installed from local source (pulls darnit-core from the same context).
COPY packages/ /opt/amber/packages/
RUN pip install --no-cache-dir \
        /opt/amber/packages/darnit \
        /opt/amber/packages/darnit-reproducibility

# gittuf — the artifact under test, built from the vendored source.
COPY gittuf-src/ /opt/gittuf/
RUN cd /opt/gittuf \
    && CGO_ENABLED=0 go build -trimpath -o /usr/local/bin/gittuf . \
    && gittuf version

WORKDIR /work
ENTRYPOINT ["amber"]
CMD ["--help"]
