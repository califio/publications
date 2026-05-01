FROM php:8.5-apache

# Apache prefork is default in this image. Ensure it's configured.
RUN a2dismod mpm_event 2>/dev/null; a2enmod mpm_prefork 2>/dev/null; true

# Deploy the vulnerable app
COPY remote_app.php /var/www/html/remote_app.php

# Make DocumentRoot writable by www-data (for webshell deployment)
RUN chmod o+w /var/www/html

# Increase prefork workers so we survive probing
RUN echo '\nMaxRequestWorkers 256\nServerLimit 256\nStartServers 16\nMinSpareServers 8\nMaxSpareServers 32' >> /etc/apache2/apache2.conf

EXPOSE 80
