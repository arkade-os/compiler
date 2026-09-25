FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY app /usr/share/nginx/html/app
COPY artifacts /usr/share/nginx/html/artifacts
COPY contracts /usr/share/nginx/html/contracts
COPY README.md DECISIONS.md /usr/share/nginx/html/

EXPOSE 80

HEALTHCHECK CMD wget -q -O /dev/null http://127.0.0.1/app/ || exit 1
