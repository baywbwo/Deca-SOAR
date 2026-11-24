# Lab only: Temporal server 1.32.2 (MIT) as a container, standing in for the systemd host of
# deploy/temporal. Same scripts and config as production. The binaries come from the official
# releases (deploy/temporal/SOURCE.txt) and are checked again here. Build with
#   deploy/lab/build-temporal.sh <dir from fetch-temporal.sh>
# which assembles a small context (temporal-bin/ + deploy/temporal) for the classic builder.
FROM debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e
RUN useradd --system --uid 10002 --home /nonexistent --shell /usr/sbin/nologin temporal
COPY temporal-bin/temporal-server temporal-bin/temporal-sql-tool /opt/temporal/1.32.2/
COPY temporal-bin/temporal /opt/temporal/cli/temporal
RUN cd /opt/temporal && printf '%s\n' \
      "f4a52911a0ce909d623475d048a1994329dada035c66a050d0440d8b6958b85e  1.32.2/temporal-server" \
      "c90014f9a3400fa245205f6dc402ebd105f5cbbd65139985a092a360d70bd71b  1.32.2/temporal-sql-tool" \
      "960afddde142595ea4bf6c74f0213b4634a4ef2ef8778c2e930af2cce30d7c8a  cli/temporal" | sha256sum -c -
COPY deploy/temporal/bin/ /opt/temporal/bin/
COPY deploy/temporal/config/ /etc/deca-soar/temporal/config/
COPY deploy/temporal/dynamicconfig/ /etc/deca-soar/temporal/dynamicconfig/
ENV TEMPORAL_BIN_DIR=/opt/temporal/1.32.2 TEMPORAL_CONFIG_DIR=/etc/deca-soar/temporal/config \
    DYNAMIC_CONFIG_FILE_PATH=/etc/deca-soar/temporal/dynamicconfig/production.yaml \
    TEMPORAL_CLI=/opt/temporal/cli/temporal
USER 10002:10002
# Schema create/upgrade is idempotent (temporal-schema.sh), then the server with the production config.
ENTRYPOINT ["/bin/sh", "-c", "/opt/temporal/bin/temporal-schema.sh && exec /opt/temporal/bin/temporal-start.sh"]
