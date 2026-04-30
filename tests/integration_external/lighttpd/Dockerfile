FROM alpine:3.20

RUN apk add --no-cache lighttpd

RUN mkdir -p /etc/lighttpd /var/log/lighttpd /var/www/localhost/htdocs

COPY lighttpd.conf /etc/lighttpd/lighttpd.conf
COPY www/index.html /var/www/localhost/htdocs/index.html

EXPOSE 80

CMD ["lighttpd", "-D", "-f", "/etc/lighttpd/lighttpd.conf"]
