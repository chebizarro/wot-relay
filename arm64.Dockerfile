# Use Golang image based on Debian Bookworm
FROM golang:bookworm

# Provenance, injected by the build workflow. Defaults make an ad-hoc build
# visibly unlabelled rather than silently claiming a revision.
ARG GIT_COMMIT=unknown
ARG SOURCE_URL=https://github.com/bitvora/wot-relay
ARG BUILD_TIME=
LABEL org.opencontainers.image.title="wot-relay" \
      org.opencontainers.image.description="Web-of-trust Nostr relay (khatru + nostrlib LMDB eventstore)" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.created="${BUILD_TIME}" \
      org.opencontainers.image.version="git-${GIT_COMMIT}"

# Set the working directory within the container
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Set fixed environment variables
ENV DB_PATH="db"
ENV INDEX_PATH="templates/index.html"
ENV STATIC_PATH="templates/static"

# touch a .env (https://github.com/bitvora/wot-relay/pull/4)
RUN touch .env

# Build the Go application. CGO is required: PowerDNS/lmdb-go compiles the LMDB
# C sources into the binary. Link-time -X vars carry build provenance, and
# `go version -m` records the exact module graph in /app/PROVENANCE.txt.
RUN CGO_ENABLED=1 go build -trimpath \
      -ldflags "-X main.buildRevision=${GIT_COMMIT} -X main.buildSource=${SOURCE_URL} -X main.buildTime=${BUILD_TIME}" \
      -o main . \
    && { echo "revision=${GIT_COMMIT}"; echo "source=${SOURCE_URL}"; echo "build_time=${BUILD_TIME}"; echo; \
         go version -m main; } > /app/PROVENANCE.txt

# Expose the port that the application will run on
EXPOSE 3334

# Set the command to run the executable
CMD ["./main"]
