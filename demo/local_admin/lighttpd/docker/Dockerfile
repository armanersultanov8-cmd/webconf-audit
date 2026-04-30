FROM alpine:3.21

RUN apk add --no-cache lighttpd openssl

RUN mkdir -p /var/www/localhost/htdocs /var/log/lighttpd /var/lib/lighttpd \
    && printf '<html><body>lighttpd demo</body></html>\n' > /var/www/localhost/htdocs/index.html \
    && openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout /var/lib/lighttpd/demo.pem \
        -out /var/lib/lighttpd/demo.pem \
        -days 365 \
        -subj "/CN=demo.local" \
    && chown -R lighttpd:lighttpd /var/www/localhost /var/log/lighttpd /var/lib/lighttpd

USER lighttpd

CMD ["lighttpd", "-D", "-f", "/etc/lighttpd/lighttpd.conf"]
