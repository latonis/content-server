FROM golang:1.21.5-alpine as base

WORKDIR /app

COPY . .

RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -o /app ./cmd/web/server.go

FROM gcr.io/distroless/static-debian11

COPY --from=base /app/posts/ ./posts/
COPY --from=base /app/templates/ ./templates/
COPY --from=base /app/server .
COPY --from=base /app/static/ ./static/

EXPOSE 8080

CMD ["/server"]