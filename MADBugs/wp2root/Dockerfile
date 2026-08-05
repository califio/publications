FROM wordpress:7.0.1-php8.3-apache AS wordpress_source

FROM php:8.1.34-apache

RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends curl libzip-dev; \
	docker-php-ext-install -j"$(nproc)" mysqli zip; \
	a2enmod rewrite; \
	sed -ri 's!^Listen 80$!Listen 8083!' /etc/apache2/ports.conf; \
	sed -ri 's!<VirtualHost \\*:80>!<VirtualHost *:8083>!' /etc/apache2/sites-available/000-default.conf; \
	rm -rf /var/lib/apt/lists/*

COPY --from=wordpress_source /usr/src/wordpress /usr/src/wordpress
COPY --from=wordpress_source /usr/local/bin/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY docker/php-lab.ini /usr/local/etc/php/conf.d/zz-wp2shell-lab.ini
COPY docker/health.php /usr/src/wordpress/__apache-health.php

RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh; \
	chown -R www-data:www-data /usr/src/wordpress

WORKDIR /var/www/html

EXPOSE 8083

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["apache2-foreground"]
