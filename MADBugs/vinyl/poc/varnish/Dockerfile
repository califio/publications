# Use the official Varnish image. The Tstrcmp prefix-match behaviour that
# underpins this exploit has been in h2h_addhdr since Varnish's HTTP/2
# implementation was introduced in 2016 (commit 66d268264) and is unchanged
# in upstream master at the time of writing. varnish:7.6 (latest stable)
# carries the bug verbatim.
FROM varnish:7.6

COPY default.vcl /etc/varnish/default.vcl
COPY entrypoint.sh /entrypoint.sh
USER root
RUN chmod +x /entrypoint.sh
USER varnish

EXPOSE 80 6086
ENTRYPOINT ["/entrypoint.sh"]
