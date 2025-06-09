FROM alpine:3.20 AS builder

WORKDIR /tmp

# Install required packages
RUN apk update \
    && apk add --no-cache linux-headers alpine-sdk cmake tcl openssl-dev zlib-dev spdlog spdlog-dev \
    && rm -rf /var/cache/apk/*

# Clone, build and install belabox-patched SRT
RUN git clone https://github.com/onsmith/srt.git srt \
    && cd srt \
    && ./configure \
    && make -j${nproc} \
    && make install

# Clone and build SRT Live Server
COPY . /tmp/srt-live-server
RUN cd srt-live-server \
    && make -j8

# Runtime image
FROM alpine:3.20

ENV LD_LIBRARY_PATH=/lib:/usr/lib:/usr/local/lib64

# Install runtime dependencies
RUN apk update \
    && apk add --no-cache openssl libstdc++ supervisor coreutils spdlog perl \
    && rm -rf /var/cache/apk/*

# Copy binaries from the builder stage
COPY --from=builder /tmp/srt-live-server/bin /usr/local/bin
COPY --from=builder /usr/local/bin/srt-* /usr/local/bin
COPY --from=builder /usr/local/lib/libsrt* /usr/local/lib

# copy configuration files
COPY sls.conf /etc/sls/

# expose ports
# Publisher port, Player port, HTTP API port
EXPOSE 4001/udp 4000/udp 8080/tcp

# run the server
CMD ["/usr/local/bin/sls", "-c", "/etc/sls/sls.conf"]
