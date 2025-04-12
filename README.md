# content-server

I wanted to build something with go templates and htmx, so here we are. This is a webserver that loads pages via markdown and converts them to html (read: htmx, barely) and then delivers the content to the user.

I needed a mechanism for sharing my #100DaysofYARA content, so I decided to build one.

# Development

## Air
```bash
air
```

## Go

```bash
go run cmd/web/server.go
```

## Tailwind

```bash
npx @tailwindcss/cli -i ./static/main.css -o ./static/output.css --watc
```