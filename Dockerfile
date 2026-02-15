FROM alpine:3.20 AS builder

WORKDIR /tmp

# Install required packages
RUN apk update \
    && apk add --no-cache linux-headers alpine-sdk cmake tcl openssl-dev zlib-dev spdlog spdlog-dev sqlite-dev \
    && rm -rf /var/cache/apk/* \
    && git clone https://github.com/yhirose/cpp-httplib.git /tmp/cpp-httplib \
    && cp /tmp/cpp-httplib/httplib.h /usr/include/ \
    && rm -rf /tmp/cpp-httplib

# Clone, build and install belabox-patched SRT
RUN git clone -b feature/srtla-stats https://github.com/OpenIRL/srt.git srt \
    && cd srt \
    && ./configure \
    && make -j$(nproc) \
    && make install

# Clone and build SRT Live Server
COPY . /tmp/srt-live-server
RUN cd srt-live-server \
    && make -j$(nproc)

# Runtime image
FROM alpine:3.20

ENV LD_LIBRARY_PATH=/lib:/usr/lib:/usr/local/lib64

# Install runtime dependencies
RUN apk update \
    && apk add --no-cache openssl libstdc++ supervisor coreutils procps net-tools sqlite sqlite-dev \
    && rm -rf /var/cache/apk/*

# Copy binaries from the builder stage
COPY --from=builder /tmp/srt-live-server/bin /usr/local/bin
COPY --from=builder /usr/local/bin/srt-* /usr/local/bin
COPY --from=builder /usr/local/lib/libsrt* /usr/local/lib
COPY --from=builder /usr/include/httplib.h /usr/include/

# copy configuration files
COPY sls.conf /etc/sls/

# Create necessary directories with proper permissions
RUN mkdir -p /etc/sls /var/lib/sls /tmp/sls && \
    chmod 755 /etc/sls /var/lib/sls /tmp/sls && \
    chmod 666 /etc/sls/sls.conf

# expose ports
# Publisher port, Player port, HTTP API port
EXPOSE 4000/udp
EXPOSE 4001/udp
EXPOSE 8080/tcp

# run the server
CMD ["/usr/local/bin/sls", "-c", "/etc/sls/sls.conf"]
