FROM golang:1.24-alpine AS base

WORKDIR /app

COPY . .

RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -o /app ./cmd/web/server.go

FROM gcr.io/distroless/static-debian11

COPY --from=base /app/content/ ./content/
COPY --from=base /app/templates/ ./templates/
COPY --from=base /app/server .
COPY --from=base /app/static/ ./static/

EXPOSE 8080

CMD ["/server"]