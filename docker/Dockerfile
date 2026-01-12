# Tor Docker image for integration testing
FROM alpine:3.19

RUN apk add --no-cache tor

# Create data directory with proper permissions
RUN mkdir -p /var/lib/tor && \
    chown -R tor:tor /var/lib/tor && \
    chmod 700 /var/lib/tor

# Copy configuration
COPY torrc /etc/tor/torrc

# Expose ports
EXPOSE 9050 9051

# Run as tor user
USER tor

# Start Tor
CMD ["tor", "-f", "/etc/tor/torrc"]
